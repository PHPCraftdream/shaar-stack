"""CI-only real loopback contracts for unprivileged workers, not product/NAT proof."""

import asyncio
import importlib.util
from pathlib import Path
import socket
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("shaar_product_worker", Path(__file__).resolve().parents[1] / "worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
NONCE = "a" * 32


class PayloadTests(unittest.TestCase):
    def test_payloads_are_distinct_binary_bounded_and_nonce_bound(self):
        request, reply = worker.payloads(NONCE)
        self.assertNotEqual(request, reply)
        self.assertIn(b"\x00\xff", request)
        self.assertLessEqual(len(request), 65536)
        self.assertLessEqual(len(reply), 65536)
        self.assertNotEqual(worker.payloads("b" * 32), (request, reply))
        for nonce in ("", "A" * 32, "a" * 31, "a" * 33, "a" * 31 + "\n"):
            with self.assertRaises(ValueError):
                worker.payloads(nonce)


class WorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.events = asyncio.Queue(maxsize=16)
        self.patch = mock.patch.object(worker, "emit", side_effect=lambda label, nonce, role, **values:
                                      self.events.put_nowait((label, role, values)))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.tasks = []
        self.sockets = []

    async def asyncTearDown(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for stream in self.sockets:
            stream.close()

    def start(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.append(task)
        return task

    def bind(self):
        bound = worker.listener(0)
        self.sockets.append(bound)
        return bound

    async def ready(self, role):
        label, actual, value = await asyncio.wait_for(self.events.get(), 5)
        self.assertEqual((label, actual), ("SHAAR_NAT_READY", role))
        return value

    def stop(self, reader, nonce=NONCE):
        reader.feed_data(("STOP " + nonce + "\n").encode("ascii"))
        reader.feed_eof()

    async def test_exact_app_half_close_eof_and_target_stop(self):
        bound, reader = self.bind(), asyncio.StreamReader(limit=64)
        target = self.start(worker.target(NONCE, False, bound, reader))
        await self.ready("target")
        app = self.start(worker.app(NONCE, False, bound.getsockname()[1]))
        self.assertTrue((await self.ready("app"))["admitted"])
        response = await asyncio.wait_for(app, 5)
        self.assertFalse(response["denied"])
        self.stop(reader)
        result = await asyncio.wait_for(target, 5)
        request, reply = worker.payloads(NONCE)
        self.assertEqual(result, {"accepts": 1, "request_bytes": len(request), "reply_bytes": len(reply)})
        self.assertEqual(response["attempts"], 1)
        self.assertEqual(bound.fileno(), -1)

    async def test_denied_target_has_zero_admissions_until_terminal_stop(self):
        bound, reader = self.bind(), asyncio.StreamReader(limit=64)
        target = self.start(worker.target(NONCE, True, bound, reader))
        await self.ready("target")
        self.stop(reader)
        self.assertEqual(await asyncio.wait_for(target, 5), {"accepts": 0, "request_bytes": 0, "reply_bytes": 0})

    async def test_denied_target_rejects_a_real_tcp_admission(self):
        bound, reader = self.bind(), asyncio.StreamReader(limit=64)
        port = bound.getsockname()[1]
        target = self.start(worker.target(NONCE, True, bound, reader))
        await self.ready("target")
        stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sockets.append(stream)
        stream.setblocking(False)
        await asyncio.get_running_loop().sock_connect(stream, ("127.0.0.1", port))
        with self.assertRaisesRegex(ValueError, "unexpected fixed-target TCP admission"):
            await asyncio.wait_for(target, 5)

    async def endpoint(self, bound, reply, hold=None):
        stream, _ = await asyncio.get_running_loop().sock_accept(bound)
        try:
            await worker.exact_eof(stream, worker.payloads(NONCE)[0])
            if hold is not None:
                await hold.wait()
            if reply:
                await asyncio.get_running_loop().sock_sendall(stream, reply)
        finally:
            stream.close()

    async def test_signal_app_requires_terminal_eof_and_rejects_any_reply_byte(self):
        for reply in (b"", b"forbidden"):
            with self.subTest(reply=reply):
                bound = self.bind()
                endpoint = self.start(self.endpoint(bound, reply))
                if reply:
                    with self.assertRaisesRegex(ValueError, "unexpectedly returned application bytes"):
                        await asyncio.wait_for(worker.app(NONCE, True, bound.getsockname()[1]), 5)
                else:
                    result = await asyncio.wait_for(worker.app(NONCE, True, bound.getsockname()[1]), 5)
                    self.assertEqual((result["denied"], result["terminal"], result["reply_bytes"]), (True, "eof", 0))
                await endpoint

    async def test_silent_admitted_stream_times_out_instead_of_passing_denial(self):
        bound = self.bind()
        endpoint = self.start(self.endpoint(bound, b"", asyncio.Event()))
        with mock.patch.object(worker, "IO_SECONDS", 1):
            with self.assertRaises(TimeoutError):
                await worker.app(NONCE, True, bound.getsockname()[1])
        endpoint.cancel()
        await asyncio.gather(endpoint, return_exceptions=True)

    async def test_partial_or_wrong_reply_is_terminal_not_a_retry(self):
        for reply in (worker.payloads(NONCE)[1][:4], b"wrong"):
            with self.subTest(reply=reply):
                bound = self.bind()
                endpoint = self.start(self.endpoint(bound, reply))
                with self.assertRaises(ValueError):
                    await asyncio.wait_for(worker.app(NONCE, False, bound.getsockname()[1]), 5)
                await endpoint

    async def test_reset_after_partial_reply_is_not_a_retryable_empty_stream(self):
        expected = worker.payloads(NONCE)[1]
        reads = mock.AsyncMock(side_effect=[expected[:4], ConnectionResetError(104, "reset")])
        with mock.patch.object(asyncio.get_running_loop(), "sock_recv", reads):
            with self.assertRaisesRegex(ValueError, "partial reply bytes"):
                await worker.exact_eof(mock.Mock(), expected)
        self.assertEqual(reads.await_count, 2)

    async def test_stop_frames_reject_oversize_trailing_and_truncated_input(self):
        for frame in (b"x" * 65, ("STOP " + NONCE + "\nextra").encode("ascii"), b"STOP "):
            reader = asyncio.StreamReader(limit=64)
            reader.feed_data(frame)
            reader.feed_eof()
            with self.subTest(frame=frame[:16]), self.assertRaises((ValueError, asyncio.LimitOverrunError, asyncio.IncompleteReadError)):
                await worker.stop_frame(reader, NONCE)

    async def test_cli_rejects_root_before_opening_any_worker_socket(self):
        args = mock.Mock(nonce=NONCE, role="target", deny=True)
        with mock.patch.object(worker.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "must be unprivileged"):
                await worker.main(args)

    async def test_bad_stop_and_cancellation_close_the_owned_listener(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                bound, reader = self.bind(), asyncio.StreamReader(limit=64)
                target = self.start(worker.target(NONCE, True, bound, reader))
                await self.ready("target")
                if cancel:
                    target.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await target
                else:
                    self.stop(reader, "b" * 32)
                    with self.assertRaises(ValueError):
                        await target
                self.assertEqual(bound.fileno(), -1)

    async def test_stop_role_sends_one_nonce_bound_frame_and_rejects_bad_bounds(self):
        received = asyncio.Queue(maxsize=1)

        async def serve(reader, writer):
            received.put_nowait(await reader.read())
            writer.close()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            await worker.stop(NONCE, port)
            self.assertEqual(await asyncio.wait_for(received.get(), 5), b"STOP " + NONCE.encode() + bytes([10]))
        for args in (mock.Mock(nonce=NONCE, role="stop", deny=False, port=80, deadline=40),
                     mock.Mock(nonce=NONCE, role="app", deny=False, port=0, deadline=0),
                     mock.Mock(nonce=NONCE, role="app", deny=False, port=0, deadline=worker.MAX_DEADLINE + 1)):
            with self.subTest(role=args.role, deadline=args.deadline), mock.patch.object(worker.os, "geteuid", return_value=1000):
                with self.assertRaises(ValueError):
                    await worker.main(args)
