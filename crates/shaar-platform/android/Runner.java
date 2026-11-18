package dev.shaar.harness;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Test harness: starts one named command inside the app sandbox.
 * Extras: name (log label) and argv (whitespace-separated words).
 * Output goes to files/NAME.log, the exit code to files/NAME.exit.
 * Only the shaar executables of the native library directory can be started
 * ("@LIB@/libshaar_*.so"); "@FILES@" expands to the app files directory;
 * argv "@echo PORT" starts a loopback echo service, the forward target of the tests.
 * The screen shows each command and follows its log, in muted colors, wrapped to the width.
 */
public final class Runner extends Activity {
    private static final String LIB = "@LIB@/libshaar_";

    // Muted palette: dark panel, soft text, no saturated colors.
    private static final int BG = 0xFF14171D;
    private static final int PANEL = 0xFF1B1F27;
    private static final int TITLE = 0xFFE3E8EF;
    private static final int TEXT = 0xFFB4BCC8;
    private static final int DIM = 0xFF727B89;
    private static final int BLUE = 0xFF86A9D6;
    private static final int GREEN = 0xFF93BFA3;
    private static final int AMBER = 0xFFD4B483;
    private static final int RED = 0xFFD58E8E;

    private static final int MAX_LINES = 400;
    private static final int MAX_LINE_CHARS = 400;
    private static final long TICK_MS = 700;
    private static final Pattern HEX = Pattern.compile("\\b([0-9a-f]{8})[0-9a-f]{52}([0-9a-f]{4})\\b");

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ArrayDeque<CharSequence> lines = new ArrayDeque<>();
    private final List<Tail> tails = new ArrayList<>();
    private TextView view;
    private TextView status;
    private ScrollView scroll;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        // A sleeping or locked device moves the app to the background, where Android drops its
        // network capability (seen in live attempts 14 and 15): keep the harness on screen.
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
                | WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED
                | WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON);
        setContentView(buildScreen());
        note("ready · waiting for commands", DIM);
        launch(getIntent());
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(tick);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(tick);
        super.onPause();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        launch(intent);
    }

    private View buildScreen() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        // The window may draw under the system bars: keep the content clear of them.
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(0, insets.getSystemWindowInsetTop(), 0, insets.getSystemWindowInsetBottom());
            return insets;
        });

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(20), dp(16), dp(20), dp(10));
        TextView title = label("Shaar harness", 20, TITLE);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        header.addView(title, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        status = label("", 12, DIM);
        header.addView(status);
        root.addView(header);

        view = label("", 11.5f, TEXT);
        view.setTypeface(Typeface.MONOSPACE);
        view.setLineSpacing(dp(2), 1f);
        view.setTextIsSelectable(true);
        view.setPadding(dp(14), dp(12), dp(14), dp(12));
        scroll = new ScrollView(this);
        scroll.setBackground(rounded(PANEL, dp(14)));
        scroll.addView(view);
        LinearLayout.LayoutParams panel = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        panel.setMargins(dp(12), dp(2), dp(12), dp(12));
        root.addView(scroll, panel);
        return root;
    }

    private TextView label(String text, float sp, int color) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        label.setTextColor(color);
        return label;
    }

    private int dp(float value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private static GradientDrawable rounded(int color, int radius) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(color);
        shape.setCornerRadius(radius);
        return shape;
    }

    /** Polls the logs of the running commands while the screen is in front. */
    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            boolean changed = false;
            for (Iterator<Tail> it = tails.iterator(); it.hasNext();) {
                Tail tail = it.next();
                for (String text : tail.poll()) {
                    lines.addLast(colored(text));
                    changed = true;
                }
                String code = tail.exitCode();
                if (code != null) {
                    for (String text : tail.poll()) {
                        lines.addLast(colored(text));
                    }
                    lines.addLast(exitLine(tail.name, code));
                    it.remove();
                    changed = true;
                }
            }
            if (changed) {
                render();
            }
            boolean busy = !tails.isEmpty();
            status.setText(busy ? "● " + tails.size() + " running" : "○ idle");
            status.setTextColor(busy ? GREEN : DIM);
            handler.postDelayed(this, TICK_MS);
        }
    };

    private void render() {
        while (lines.size() > MAX_LINES) {
            lines.removeFirst();
        }
        SpannableStringBuilder all = new SpannableStringBuilder();
        for (CharSequence line : lines) {
            all.append(line).append('\n');
        }
        View content = scroll.getChildAt(0);
        boolean follow = content.getBottom() - (scroll.getScrollY() + scroll.getHeight()) < dp(48);
        view.setText(all);
        if (follow) {
            scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
        }
    }

    private static void span(SpannableStringBuilder out, String text, int color, boolean bold) {
        int start = out.length();
        out.append(text);
        out.setSpan(new ForegroundColorSpan(color), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        if (bold) {
            out.setSpan(new StyleSpan(Typeface.BOLD), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
    }

    private static String clock() {
        return new SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(new Date());
    }

    /** Long keys are shortened for the screen only; the log files keep them whole. */
    private static String shorten(String text) {
        String shown = HEX.matcher(text).replaceAll("$1…$2");
        return shown.length() > MAX_LINE_CHARS ? shown.substring(0, MAX_LINE_CHARS) + "…" : shown;
    }

    private static CharSequence colored(String raw) {
        String text = shorten(raw);
        SpannableStringBuilder out = new SpannableStringBuilder();
        span(out, text, colorOf(text), false);
        return out;
    }

    private static int colorOf(String text) {
        String s = text.toLowerCase(Locale.ROOT);
        if (s.contains("error") || s.contains("panic") || s.contains("failed") || s.contains("refused")) {
            return RED;
        }
        if (s.contains("fallback") || s.contains("timeout") || s.contains("bounded")
                || s.contains("cachemiss") || s.contains("dropped")
                || s.contains("found=no") || s.contains("connected=no")) {
            return AMBER;
        }
        if (s.contains("outcome=ok") || s.contains("outcome=found") || s.contains("result=ok")
                || s.contains("connected=yes") || s.contains("found=yes")) {
            return GREEN;
        }
        if (s.contains("route path") || s.contains("session path") || s.contains("listening=")
                || s.contains("bound=")) {
            return BLUE;
        }
        if (s.startsWith("shaar: dht")) {
            return DIM;
        }
        return TEXT;
    }

    private void note(String text, int color) {
        SpannableStringBuilder out = new SpannableStringBuilder();
        span(out, text, color, false);
        lines.addLast(out);
        render();
    }

    private void commandLine(String name, String argv) {
        SpannableStringBuilder out = new SpannableStringBuilder();
        span(out, clock() + " ", DIM, false);
        span(out, "▸ " + name + " ", BLUE, true);
        span(out, shorten(argv.replace("@LIB@/libshaar_", "shaar-").replace(".so", "")
                .replace("@FILES@", "~")), DIM, false);
        lines.addLast(out);
        render();
    }

    private static CharSequence exitLine(String name, String code) {
        SpannableStringBuilder out = new SpannableStringBuilder();
        span(out, clock() + " ", DIM, false);
        span(out, "■ " + name + " exit " + code, code.equals("0") ? GREEN : RED, true);
        return out;
    }

    /**
     * Keeps the app a foreground service while the commands run: when the screen turns off or
     * another app comes up, the activity stops and Android takes the network away from a plain
     * app (seen in live attempts 14, 15 and 18); a foreground service keeps it.
     */
    public static final class Keeper extends Service {
        @Override
        public IBinder onBind(Intent intent) {
            return null;
        }

        @Override
        public int onStartCommand(Intent intent, int flags, int startId) {
            NotificationManager manager = getSystemService(NotificationManager.class);
            manager.createNotificationChannel(new NotificationChannel(
                    "harness", "Shaar harness", NotificationManager.IMPORTANCE_LOW));
            Notification note = new Notification.Builder(this, "harness")
                    .setContentTitle("Shaar harness running")
                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                    .build();
            startForeground(1, note, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
            return START_NOT_STICKY;
        }
    }

    /** Reads the new whole lines of one command's log and its exit code, read-only. */
    private static final class Tail {
        final String name;
        private final File log;
        private final File exit;
        private final StringBuilder partial = new StringBuilder();
        private long offset;

        Tail(File files, String name) {
            this.name = name;
            this.log = new File(files, name + ".log");
            this.exit = new File(files, name + ".exit");
        }

        List<String> poll() {
            List<String> out = new ArrayList<>();
            try (RandomAccessFile in = new RandomAccessFile(log, "r")) {
                long length = in.length();
                if (length < offset) {
                    offset = 0;
                }
                int take = (int) Math.min(length - offset, 64 * 1024);
                if (take > 0) {
                    byte[] buffer = new byte[take];
                    in.seek(offset);
                    in.readFully(buffer);
                    offset += take;
                    partial.append(new String(buffer, StandardCharsets.UTF_8));
                }
            } catch (IOException ignored) {
                // The command has not created its log yet.
            }
            int cut;
            while ((cut = partial.indexOf("\n")) >= 0) {
                out.add(partial.substring(0, cut).replace("\r", ""));
                partial.delete(0, cut + 1);
            }
            if (partial.length() > MAX_LINE_CHARS) {
                out.add(partial.toString());
                partial.setLength(0);
            }
            return out;
        }

        String exitCode() {
            try (RandomAccessFile in = new RandomAccessFile(exit, "r")) {
                byte[] buffer = new byte[(int) Math.min(in.length(), 256)];
                in.readFully(buffer);
                String code = new String(buffer, StandardCharsets.UTF_8).trim();
                return code.isEmpty() ? null : code;
            } catch (IOException e) {
                return null;
            }
        }
    }

    private void launch(Intent intent) {
        String name = intent.getStringExtra("name");
        String argv = intent.getStringExtra("argv");
        if (name == null || argv == null) {
            return;
        }
        startForegroundService(new Intent(this, Keeper.class));
        if (!name.matches("[A-Za-z0-9_-]{1,32}")) {
            note("refused: bad name", RED);
            return;
        }
        File files = getFilesDir();
        new File(files, name + ".log").delete();
        new File(files, name + ".exit").delete();
        String[] words = argv.trim().split("\\s+");
        commandLine(name, argv);
        if (words.length == 2 && words[0].equals("@echo") && words[1].matches("[0-9]{1,5}")) {
            watch(files, name);
            echo(files, name, Integer.parseInt(words[1]));
            return;
        }
        if (!words[0].startsWith(LIB) || !words[0].endsWith(".so")
                || words[0].indexOf('/', LIB.indexOf('/') + 1) >= 0) {
            note("refused: only shaar executables", RED);
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
        watch(files, name);
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

    /** Follows the log of a command; a command started again under the same name replaces it. */
    private void watch(File files, String name) {
        for (Iterator<Tail> it = tails.iterator(); it.hasNext();) {
            if (it.next().name.equals(name)) {
                it.remove();
            }
        }
        tails.add(new Tail(files, name));
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
