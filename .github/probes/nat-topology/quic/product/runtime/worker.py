"""Unprivileged fixed-target/APP workers for the four controlled product cases."""

import argparse
import asyncio
import errno
import json
import os
import re
import socket
import sys

FRONT_PORT = 48001
TARGET_PORT = 48002
MAX_ATTEMPTS = 16
IO_SECONDS = 40
LIFETIME_SECONDS = 125
MAX_DEADLINE = 85
TRANSIENT = {errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE}


def payloads(nonce):
    if type(nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("worker nonce must be exactly 32 lowercase hex characters")
    return (b"shaar-controlled-request:" + nonce.encode("ascii") + b"\x00\xff\x80\n",
            b"shaar-fixed-target-reply:" + nonce.encode("ascii") + b"\xff\x00\x81\n")


def emit(label, nonce, role, **values):
    print(label + " " + json.dumps({"nonce": nonce, "role": role, "pid": os.getpid(), **values},
                                  separators=(",", ":")), flush=True)


def listener(port):
    result = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        result.setblocking(False)
        result.bind(("127.0.0.1", port))
        result.listen(2)
        return result
    except BaseException:
        result.close()
        raise


async def exact_eof(stream, expected):
    """Reject wrong/extra/partial bytes; an empty stream is a typed transient only at the caller."""
    loop = asyncio.get_running_loop()
    received = bytearray()
    while True:
        try:
            block = await loop.sock_recv(stream, min(4096, len(expected) + 1 - len(received)))
        except OSError as error:
            if received:
                raise ValueError("APP stream failed after partial reply bytes") from error
            raise
        if not block:
            if not received:
                raise ConnectionResetError(errno.ECONNRESET, "empty stream before expected APP bytes")
            if bytes(received) != expected:
                raise ValueError("APP stream ended with incomplete bytes")
            return len(received)
        received.extend(block)
        if not expected.startswith(received):
            raise ValueError("APP stream returned wrong or extra bytes")


async def exchange_target(stream, request, reply):
    try:
        async with asyncio.timeout(IO_SECONDS):
            count = await exact_eof(stream, request)
            await asyncio.get_running_loop().sock_sendall(stream, reply)
            stream.shutdown(socket.SHUT_WR)
            return {"request_bytes": count, "reply_bytes": len(reply)}
    finally:
        stream.close()


def merge_receipts(completed, new):
    """Sum per-connection receipts; the target result reports exact totals across all accepted APP streams."""
    if completed is None:
        return dict(new)
    return {key: completed[key] + new[key] for key in completed}


async def stop_frame(reader, nonce):
    frame = await reader.readuntil(b"\n")
    if frame != ("STOP " + nonce + "\n").encode("ascii") or await reader.read(1) != b"":
        raise ValueError("target stop frame must be nonce-bound and terminal")


async def target(nonce, denied, bound, control, expected=None):
    """expected: exact number of APP streams to accept (default 1, or 0 when denied); a further admission is a failure."""
    if expected is None:
        expected = 0 if denied else 1
    request, reply = payloads(nonce)
    loop = asyncio.get_running_loop()
    accept, stop, active = None, None, set()
    accepted, completed = 0, None
    try:
        stop = asyncio.create_task(stop_frame(control, nonce))
        accept = asyncio.create_task(loop.sock_accept(bound))
        emit("SHAAR_NAT_READY", nonce, "target", port=bound.getsockname()[1])
        async with asyncio.timeout(LIFETIME_SECONDS):
            while True:
                done, _ = await asyncio.wait({accept, stop, *active}, return_when=asyncio.FIRST_COMPLETED)
                if accept in done:
                    stream, address = accept.result()
                    accepted += 1
                    if address[0] != "127.0.0.1" or denied or accepted > expected:
                        stream.close()
                        raise ValueError("unexpected fixed-target TCP admission")
                    stream.setblocking(False)
                    active.add(asyncio.create_task(exchange_target(stream, request, reply)))
                    accept = asyncio.create_task(loop.sock_accept(bound))
                for task in done & active:
                    active.remove(task)
                    completed = merge_receipts(completed, task.result())
                if stop in done:
                    stop.result()
                    if active or accepted != expected or (expected and completed is None):
                        raise ValueError("target stopped before its required APP outcome")
                    # Products must already be reaped before the controller sends STOP.
                    accept.cancel()
                    terminal_accept, = await asyncio.gather(accept, return_exceptions=True)
                    accept = None
                    if isinstance(terminal_accept, tuple):
                        terminal_accept[0].close()
                        raise ValueError("target admission raced terminal cleanup")
                    if not isinstance(terminal_accept, asyncio.CancelledError):
                        raise RuntimeError("target accept failed at terminal cleanup") from terminal_accept
                    # No accept task can consume the terminal backlog behind this check.
                    try:
                        late, _ = bound.accept()
                    except BlockingIOError:
                        pass
                    else:
                        late.close()
                        raise ValueError("late target admission at terminal cleanup boundary")
                    bound.close()
                    result = {"accepts": accepted, "request_bytes": 0, "reply_bytes": 0}
                    if completed is not None:
                        result.update(completed)
                    emit("SHAAR_NAT_RESULT", nonce, "target", **result)
                    return result
    finally:
        tasks = [task for task in (accept, stop, *active) if task is not None]
        for task in tasks:
            task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Cancellation can race a successful accept; close any returned socket.
        for result in results:
            if isinstance(result, tuple) and result and isinstance(result[0], socket.socket):
                result[0].close()
        bound.close()


async def denied_terminal(stream):
    try:
        value = await asyncio.get_running_loop().sock_recv(stream, 1)
    except OSError as error:
        if error.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE):
            return "reset"
        raise
    if value:
        raise ValueError("signal mode unexpectedly returned application bytes")
    return "eof"


async def app(nonce, denied, port=FRONT_PORT, deadline=None, attempts=MAX_ATTEMPTS, pause=None):
    request, reply = payloads(nonce)
    loop = asyncio.get_running_loop()
    admitted = False
    async with asyncio.timeout(IO_SECONDS if deadline is None else deadline):
        for attempt in range(1, attempts + 1):
            stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            stream.setblocking(False)
            try:
                await loop.sock_connect(stream, ("127.0.0.1", port))
                if not admitted:
                    emit("SHAAR_NAT_READY", nonce, "app", admitted=True, attempt=attempt)
                    admitted = True
                try:
                    await loop.sock_sendall(stream, request)
                    stream.shutdown(socket.SHUT_WR)
                except OSError as error:
                    if denied and error.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE):
                        result = {"denied": True, "terminal": "reset", "attempts": attempt, "reply_bytes": 0}
                        emit("SHAAR_NAT_RESULT", nonce, "app", **result)
                        return result
                    raise
                if denied:
                    terminal = await denied_terminal(stream)
                    result = {"denied": True, "terminal": terminal, "attempts": attempt, "reply_bytes": 0}
                else:
                    count = await exact_eof(stream, reply)
                    result = {"denied": False, "attempts": attempt, "request_bytes": len(request), "reply_bytes": count}
                emit("SHAAR_NAT_RESULT", nonce, "app", **result)
                return result
            except OSError as error:
                if error.errno not in TRANSIENT or attempt == attempts:
                    raise
            finally:
                stream.close()
            # Backoff follows an actual typed failure, never a readiness sleep.
            await asyncio.sleep(min(0.05 * 2 ** (attempt - 1), 5.0) if pause is None else pause)
    raise RuntimeError("APP attempt budget exhausted")


async def stop(nonce, port):
    """One terminal STOP frame to a loopback control listener of the same namespace."""
    _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 10)
    writer.write(("STOP " + nonce + "\n").encode("ascii"))
    await writer.drain()
    writer.close()
    await writer.wait_closed()
    emit("SHAAR_NAT_RESULT", nonce, "stop", port=port)


async def main(args):
    payloads(args.nonce)
    if os.geteuid() == 0:
        raise ValueError("ordinary APP/target workers must be unprivileged")
    if args.role == "app":
        if not 1 <= args.deadline <= MAX_DEADLINE:
            raise ValueError("APP campaign deadline outside the bounded window")
        if not 1 <= args.attempts <= MAX_ATTEMPTS or not (args.pause is None or 0.05 <= args.pause <= 10):
            raise ValueError("APP attempt budget or pause outside the bounded window")
        await app(args.nonce, args.deny, deadline=args.deadline, attempts=args.attempts, pause=args.pause)
        return
    if args.role == "stop":
        if not 1024 <= args.port <= 65535:
            raise ValueError("control port outside the owned range")
        await stop(args.nonce, args.port)
        return
    if not 0 <= args.accepts <= MAX_ATTEMPTS:
        raise ValueError("target accept budget outside the bounded window")
    control = asyncio.StreamReader(limit=64)
    transport, _ = await asyncio.get_running_loop().connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(control), sys.stdin.buffer)
    try:
        await target(args.nonce, args.deny, listener(TARGET_PORT), control, 0 if args.deny else args.accepts)
    finally:
        transport.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("target", "app", "stop"))
    parser.add_argument("nonce")
    parser.add_argument("--deny", action="store_true")
    parser.add_argument("--deadline", type=int, default=IO_SECONDS)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--attempts", type=int, default=MAX_ATTEMPTS)
    parser.add_argument("--pause", type=float, default=None)
    parser.add_argument("--accepts", type=int, default=1)
    asyncio.run(main(parser.parse_args()))
