package dev.shaar.harness;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Test harness: starts one named command inside the app sandbox.
 * Extras: name (log label) and argv (whitespace-separated words).
 * Output goes to files/NAME.log, the exit code to files/NAME.exit.
 * Only the shaar executables of the native library directory can be started
 * ("@LIB@/libshaar_*.so"); "@FILES@" expands to the app files directory;
 * argv "@echo PORT" starts a loopback echo service, the forward target of the tests.
 */
public final class Runner extends Activity {
    private static final String LIB = "@LIB@/libshaar_";
    private TextView view;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        view = new TextView(this);
        view.setText("Shaar harness: idle\n");
        setContentView(view);
        launch(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        launch(intent);
    }

    private void launch(Intent intent) {
        String name = intent.getStringExtra("name");
        String argv = intent.getStringExtra("argv");
        if (name == null || argv == null) {
            return;
        }
        if (!name.matches("[A-Za-z0-9_-]{1,32}")) {
            view.append("refused: bad name\n");
            return;
        }
        File files = getFilesDir();
        new File(files, name + ".log").delete();
        new File(files, name + ".exit").delete();
        String[] words = argv.trim().split("\\s+");
        view.append(name + ": " + argv + "\n");
        if (words.length == 2 && words[0].equals("@echo") && words[1].matches("[0-9]{1,5}")) {
            echo(files, name, Integer.parseInt(words[1]));
            return;
        }
        if (!words[0].startsWith(LIB) || !words[0].endsWith(".so")
                || words[0].indexOf('/', LIB.indexOf('/') + 1) >= 0) {
            view.append("refused: only shaar executables\n");
            return;
        }
        String[] command = new String[words.length];
        command[0] = new File(getApplicationInfo().nativeLibraryDir,
                words[0].substring("@LIB@/".length())).getPath();
        for (int i = 1; i < words.length; i++) {
            command[i] = words[i].replace("@FILES@", files.getPath());
        }
        ProcessBuilder builder = new ProcessBuilder(command)
                .directory(files)
                .redirectErrorStream(true)
                .redirectOutput(new File(files, name + ".log"));
        builder.environment().put("HOME", files.getPath());
        builder.environment().put("TMPDIR", files.getPath());
        new Thread(() -> {
            String code;
            try {
                code = Integer.toString(builder.start().waitFor());
            } catch (IOException | InterruptedException e) {
                code = "error " + e;
            }
            write(files, name + ".exit", code + "\n");
        }).start();
    }

    private static void echo(File files, String name, int port) {
        new Thread(() -> {
            try (ServerSocket server = new ServerSocket(port, 16, InetAddress.getByName("127.0.0.1"))) {
                write(files, name + ".log", "listening=127.0.0.1:" + port + "\n");
                while (true) {
                    Socket socket = server.accept();
                    new Thread(() -> pipe(socket)).start();
                }
            } catch (IOException e) {
                write(files, name + ".exit", "error " + e + "\n");
            }
        }).start();
    }

    private static void pipe(Socket socket) {
        try (Socket owned = socket) {
            InputStream in = owned.getInputStream();
            OutputStream out = owned.getOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
                out.flush();
            }
        } catch (IOException ignored) {
            // The peer went away; the harness only needs the echoed bytes.
        }
    }

    private static void write(File files, String name, String text) {
        try (FileOutputStream out = new FileOutputStream(new File(files, name))) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // The host script treats a missing file as "not finished".
        }
    }
}
