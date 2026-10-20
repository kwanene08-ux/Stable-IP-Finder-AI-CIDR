package com.stableipfinder.ai;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.net.Uri;
import android.provider.Settings;
import androidx.core.content.FileProvider;
import org.json.*;
import android.os.*;
import android.text.*;
import android.view.*;
import android.widget.*;
import java.net.*;
import java.io.*;
import java.util.*;

public class MainActivity extends Activity {
    private EditText ipInput, portInput;
    private Spinner prefixSpinner;
    private TextView countText, resultText;
    private CheckBox authorized;
    private Button scanButton;

    private static final int ROUNDS = 50;
    private static final long MAX_HOSTS = 4096;
    private static final long MAX_ATTEMPTS = 100000;
    private static final long CONFIRM_HOSTS = 256;
    private static final int CONNECT_TIMEOUT_MS = 700;
    private static final long RATE_LIMIT_MS = 150;

    // สร้าง Public GitHub Repository และ Release APK ที่ URL นี้ก่อนใช้งานจริง
    private static final String GITHUB_LATEST_RELEASE_API =
        "https://api.github.com/repos/kwanene08-ux/Stable-IP-Finder-AI-CIDR/releases/latest";
    private volatile File downloadedUpdate = null;

    private volatile boolean scanning = false;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 20, 24, 20);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);

        TextView title = new TextView(this);
        title.setText("Stable IP Finder AI");
        title.setTextSize(25);
        title.setTypeface(null, 1);
        layout.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText(
            "CIDR Scanner • TCP • 50 รอบ\n" +
            "ทดสอบเฉพาะ IP ที่คุณได้รับอนุญาต"
        );
        subtitle.setTextSize(15);
        layout.addView(subtitle);

        addLabel(layout, "IPv4 address (กรอกเอง)");
        ipInput = new EditText(this);
        ipInput.setSingleLine(true);
        ipInput.setInputType( android.text.InputType.TYPE_CLASS_NUMBER
            | android.text.InputType.TYPE_NUMBER_FLAG_DECIMAL
            | android.text.InputType.TYPE_NUMBER_FLAG_SIGNED);
        ipInput.setHint("เช่น 1.2.3.4");
        layout.addView(ipInput);

        addLabel(layout, "Prefix length");
        prefixSpinner = new Spinner(this);
        String[] prefixes = new String[32];
        for (int i = 1; i <= 32; i++) prefixes[i - 1] = "/" + i;
        prefixSpinner.setAdapter(new ArrayAdapter<>(
            this, android.R.layout.simple_spinner_dropdown_item, prefixes));
        prefixSpinner.setSelection(24 - 1);
        layout.addView(prefixSpinner);

        countText = new TextView(this);
        countText.setTextSize(16);
        countText.setPadding(0, 12, 0, 12);
        layout.addView(countText);

        addLabel(layout, "TCP ports (คั่นด้วย comma)");
        portInput = new EditText(this);
        portInput.setSingleLine(true);
        portInput.setInputType(android.text.InputType.TYPE_CLASS_NUMBER
            | android.text.InputType.TYPE_NUMBER_FLAG_DECIMAL);
        portInput.setText("443,80");
        layout.addView(portInput);

        TextView rounds = new TextView(this);
        rounds.setText("จำนวนรอบ: 50 ต่อ IP ต่อพอร์ต");
        rounds.setPadding(0, 12, 0, 12);
        layout.addView(rounds);

        authorized = new CheckBox(this);
        authorized.setText(
            "ฉันเป็นเจ้าของ IP หรือได้รับอนุญาตให้ทดสอบช่วงนี้"
        );
        layout.addView(authorized);

        scanButton = new Button(this);
        scanButton.setText("ตรวจสอบและเริ่มสแกน");
        layout.addView(scanButton);

        Button updateButton = new Button(this);
        updateButton.setText("ตรวจสอบ / ดาวน์โหลดอัปเดต");
        layout.addView(updateButton);
        updateButton.setOnClickListener(v -> checkForUpdate());

        Button stopButton = new Button(this);
        stopButton.setText("หยุดแสดงผล / กลับ");
        layout.addView(stopButton);

        resultText = new TextView(this);
        resultText.setTextSize(14);
        resultText.setTextIsSelectable(true);
        resultText.setPadding(0, 16, 0, 20);
        layout.addView(resultText);

        setContentView(scroll);

        TextWatcher watcher = new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st,
                int c, int a) {}
            public void onTextChanged(CharSequence s, int st,
                int before, int count) { updateCount(); }
            public void afterTextChanged(Editable e) {}
        };
        ipInput.addTextChangedListener(watcher);
        prefixSpinner.setOnItemSelectedListener(
            new AdapterView.OnItemSelectedListener() {
                public void onNothingSelected(AdapterView<?> p) {}
                public void onItemSelected(AdapterView<?> p, View v,
                    int position, long id) { updateCount(); }
            });

        scanButton.setOnClickListener(v -> beginScan());
        stopButton.setOnClickListener(v -> {
            resultText.setText(
                "หากกำลังสแกน งานที่กำลังทำอาจยังดำเนินต่อ\n" +
                "โปรดรอผลรอบปัจจุบัน"
            );
        });

        updateCount();
    }

    private void addLabel(LinearLayout layout, String text) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setTextSize(16);
        label.setPadding(0, 16, 0, 4);
        layout.addView(label);
    }

    private static long parseIPv4(String text) {
        String[] parts = text.trim().split("\\.", -1);
        if (parts.length != 4) throw new IllegalArgumentException(
            "ต้องกรอก IPv4 ให้ครบ 4 ชุด เช่น 1.2.3.4"
        );

        long value = 0;
        for (String part : parts) {
            if (part.isEmpty() || !part.matches("[0-9]{1,3}")) {
                throw new IllegalArgumentException("รูปแบบ IPv4 ไม่ถูกต้อง");
            }
            int n = Integer.parseInt(part);
            if (n > 255) throw new IllegalArgumentException(
                "แต่ละชุดของ IPv4 ต้องอยู่ระหว่าง 0 ถึง 255"
            );
            value = (value << 8) | n;
        }
        return value;
    }

    private static String toIPv4(long value) {
        return ((value >>> 24) & 255) + "." +
            ((value >>> 16) & 255) + "." +
            ((value >>> 8) & 255) + "." + (value & 255);
    }

    private int prefix() {
        return prefixSpinner.getSelectedItemPosition() + 1;
    }

    private long network(long ip, int prefix) {
        long mask = (0xffffffffL << (32 - prefix)) & 0xffffffffL;
        return ip & mask;
    }

    private long addressCount(int prefix) {
        return 1L << (32 - prefix);
    }

    private void updateCount() {
        try {
            long ip = parseIPv4(ipInput.getText().toString());
            int p = prefix();
            long n = network(ip, p);
            long count = addressCount(p);
            countText.setText(
                "เครือข่าย: " + toIPv4(n) + "/" + p +
                "\nจำนวน IPv4 ทั้งหมด: " +
                String.format(Locale.US, "%,d", count) +
                "\nจำนวนสูงสุดที่แอปยอมสแกน: " + MAX_HOSTS
            );
        } catch (Exception e) {
            countText.setText("กรอก IPv4 ให้ถูกต้องเพื่อคำนวณจำนวน IP");
        }
    }

    private int[] parsePorts() {
        String raw = portInput.getText().toString().trim();
        if (raw.isEmpty()) throw new IllegalArgumentException(
            "กรุณาระบุพอร์ต เช่น 443,80"
        );

        TreeSet<Integer> unique = new TreeSet<>();
        for (String s : raw.split(",")) {
            String part = s.trim();
            if (!part.matches("[0-9]{1,5}")) {
                throw new IllegalArgumentException("รูปแบบพอร์ตไม่ถูกต้อง");
            }
            int port = Integer.parseInt(part);
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException(
                    "พอร์ตต้องอยู่ระหว่าง 1 ถึง 65535"
                );
            }
            unique.add(port);
        }

        int[] result = new int[unique.size()];
        int i = 0;
        for (int p : unique) result[i++] = p;
        return result;
    }

    private void beginScan() {
        if (scanning) return;

        final long ip;
        final int p;
        final int[] ports;
        final long net;
        final long count;
        final long first;
        final long last;
        final long hosts;
        final long attempts;

        try {
            if (!authorized.isChecked()) {
                throw new IllegalArgumentException(
                    "ต้องยืนยันสิทธิ์ทดสอบ IP ก่อน"
                );
            }

            ip = parseIPv4(ipInput.getText().toString());
            p = prefix();
            ports = parsePorts();
            net = network(ip, p);
            count = addressCount(p);

            if (count > MAX_HOSTS) {
                throw new IllegalArgumentException(
                    "ช่วงนี้มี " + String.format(Locale.US, "%,d", count) +
                    " IP เกินขีดจำกัด " + MAX_HOSTS +
                    " IP กรุณาเลือกช่วงเล็กลง"
                );
            }

            first = net;
            last = net + count - 1;
            long start = first;
            long end = last;

            // ไม่ทดสอบ network/broadcast ของ subnet /30 หรือใหญ่กว่า
            if (p <= 30) {
                start++;
                end--;
            }

            hosts = Math.max(0, end - start + 1);
            attempts = hosts * ports.length * ROUNDS;

            if (hosts == 0) {
                throw new IllegalArgumentException("ไม่มี IP ให้ทดสอบ");
            }
            if (attempts > MAX_ATTEMPTS) {
                throw new IllegalArgumentException(
                    "จำนวนการเชื่อมต่อที่ต้องทดสอบ " +
                    String.format(Locale.US, "%,d", attempts) +
                    " ครั้ง เกินขีดจำกัด " + MAX_ATTEMPTS
                );
            }
        } catch (Exception e) {
            new AlertDialog.Builder(this)
                .setTitle("ตรวจสอบข้อมูล")
                .setMessage(e.getMessage())
                .setPositiveButton("ตกลง", null)
                .show();
            return;
        }

        Runnable task = () -> {
            Thread worker = new Thread(
                () -> runScan(net, p, ports, count),
                "stable-ip-scan"
            );
            worker.start();
        };
        if (count > CONFIRM_HOSTS) {
            new AlertDialog.Builder(this)
                .setTitle("ยืนยันช่วง IP ขนาดใหญ่")
                .setMessage(
                    "เครือข่าย " + toIPv4(net) + "/" + p +
                    "\nจำนวน IP ทั้งหมด: " + count +
                    "\nจำนวนรอบ: 50 ต่อ IP ต่อพอร์ต" +
                    "\nจำนวน TCP attempts โดยประมาณ: " + attempts +
                    "\nการทดสอบอาจใช้เวลานาน ต้องมีสิทธิ์ทดสอบ"
                )
                .setNegativeButton("ยกเลิก", null)
                .setPositiveButton("ยืนยันและเริ่ม", (d, w) -> task.run())
                .show();
        } else {
            new AlertDialog.Builder(this)
                .setTitle("ยืนยันการสแกน")
                .setMessage(
                    "จะทดสอบ " + hosts + " IP จำนวน " +
                    attempts + " TCP attempts\nดำเนินการต่อหรือไม่?"
                )
                .setNegativeButton("ยกเลิก", null)
                .setPositiveButton("เริ่มสแกน", (d, w) -> task.run())
                .show();
        }
    }

    private static class Stat {
        String ip;
        int port;
        int ok;
        long totalMs;
        long bestMs = Long.MAX_VALUE;

        double avg() {
            return ok == 0 ? Double.POSITIVE_INFINITY :
                (double) totalMs / ok;
        }
    }


    private void checkForUpdate() {
        resultText.setText("กำลังตรวจสอบรุ่นล่าสุดจาก GitHub Releases...");
        new Thread(() -> {
            HttpURLConnection conn = null;
            File apk = null;
            try {
                URL api = new URL(GITHUB_LATEST_RELEASE_API);
                conn = (HttpURLConnection) api.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(20000);
                conn.setRequestProperty("Accept", "application/vnd.github+json");
                conn.setRequestProperty("User-Agent", "Stable-IP-Finder-AI");

                int code = conn.getResponseCode();
                if (code != HttpURLConnection.HTTP_OK) {
                    throw new IOException(
                        "GitHub API ตอบ HTTP " + code +
                        "\nตรวจว่า repository เป็น Public และมี Release แล้ว"
                    );
                }

                JSONObject release = new JSONObject(
                    readLimited(conn.getInputStream(), 1_000_000)
                );
                String tag = release.optString("tag_name", "latest");
                JSONArray assets = release.optJSONArray("assets");
                if (assets == null || assets.length() == 0) {
                    throw new IOException("Release นี้ไม่มีไฟล์ APK");
                }

                String downloadUrl = null;
                String assetName = null;
                for (int i = 0; i < assets.length(); i++) {
                    JSONObject asset = assets.getJSONObject(i);
                    String name = asset.optString("name", "");
                    String url = asset.optString("browser_download_url", "");
                    if (name.toLowerCase(Locale.ROOT).endsWith(".apk")
                            && url.startsWith("https://github.com/")) {
                        downloadUrl = url;
                        assetName = name;
                        break;
                    }
                }
                if (downloadUrl == null) {
                    throw new IOException(
                        "ไม่พบ APK ใน Release ล่าสุด กรุณาอัปโหลดไฟล์ .apk"
                    );
                }

                URL fileURL = new URL(downloadUrl);
                HttpURLConnection dl = (HttpURLConnection) fileURL.openConnection();
                dl.setInstanceFollowRedirects(true);
                dl.setConnectTimeout(20000);
                dl.setReadTimeout(30000);
                dl.setRequestProperty("User-Agent", "Stable-IP-Finder-AI");
                try {
                    int status = dl.getResponseCode();
                    if (status != HttpURLConnection.HTTP_OK) {
                        throw new IOException("ดาวน์โหลด APK ไม่สำเร็จ: HTTP " + status);
                    }

                    File directory = new File(getCacheDir(), "updates");
                    if (!directory.exists() && !directory.mkdirs()) {
                        throw new IOException("สร้างโฟลเดอร์ดาวน์โหลดไม่ได้");
                    }
                    apk = new File(directory, "stable-update.apk");
                    long total = 0;
                    try (InputStream in = dl.getInputStream();
                         FileOutputStream out = new FileOutputStream(apk, false)) {
                        byte[] buffer = new byte[8192];
                        int n;
                        while ((n = in.read(buffer)) != -1) {
                            total += n;
                            if (total > 100L * 1024 * 1024) {
                                throw new IOException("APK ใหญ่เกิน 100 MB");
                            }
                            out.write(buffer, 0, n);
                        }
                        out.flush();
                    }
                } finally {
                    dl.disconnect();
                }

                PackageInfo downloaded = getPackageManager()
                    .getPackageArchiveInfo(apk.getAbsolutePath(), 0);
                if (downloaded == null) {
                    throw new IOException("ไฟล์ที่ดาวน์โหลดไม่ใช่ APK ที่อ่านได้");
                }
                if (!getPackageName().equals(downloaded.packageName)) {
                    throw new IOException(
                        "Package ID ไม่ตรงกัน\nAPK: " + downloaded.packageName +
                        "\nแอปนี้: " + getPackageName()
                    );
                }

                PackageInfo current = getPackageManager()
                    .getPackageInfo(getPackageName(), 0);

                if (downloaded.versionCode <= current.versionCode) {
                    apk.delete();
                    String message = "ติดตั้งเวอร์ชัน " + current.versionName +
                        " (build " + current.versionCode + ") อยู่แล้ว\n" +
                        "Release " + tag + " มี build " + downloaded.versionCode +
                        "\nหากแก้โค้ดใหม่ ต้องเพิ่ม versionCode และเผยแพร่ APK ใหม่";
                    runOnUiThread(() -> {
                        resultText.setText(message);
                        new AlertDialog.Builder(MainActivity.this)
                            .setTitle("ยังไม่มีรุ่นใหม่")
                            .setMessage(message)
                            .setPositiveButton("ตกลง", null)
                            .show();
                    });
                    return;
                }

                downloadedUpdate = apk;
                final File readyApk = apk;
                final String readyTag = tag;
                final String readyName = assetName;
                runOnUiThread(() -> new AlertDialog.Builder(MainActivity.this)
                    .setTitle("ดาวน์โหลดอัปเดตเสร็จแล้ว")
                    .setMessage(
                        "รุ่น: " + readyTag +
                        "\nไฟล์: " + readyName +
                        "\nBuild ปัจจุบัน: " + current.versionCode +
                        "\nBuild ใหม่: " + downloaded.versionCode +
                        "\n\nกด “เปิดหน้าติดตั้ง” เพื่อให้ Android แสดงหน้าติดตั้ง " +
                        "คุณต้องตรวจสอบและกดยืนยันติดตั้งด้วยตัวเอง"
                    )
                    .setPositiveButton("เปิดหน้าติดตั้ง",
                        (dialog, which) -> installDownloadedApk(readyApk))
                    .setNegativeButton("ไว้ทีหลัง", (dialog, which) -> {
                        resultText.setText(
                            "ดาวน์โหลดแล้ว สามารถเปิดปุ่มอัปเดตอีกครั้งภายหลัง"
                        );
                    })
                    .show());

            } catch (Exception e) {
                String error = e.getMessage() == null
                    ? e.getClass().getSimpleName() : e.getMessage();
                final String msg = "ตรวจสอบ/ดาวน์โหลดอัปเดตไม่สำเร็จ\n" + error;
                runOnUiThread(() -> {
                    resultText.setText(msg);
                    new AlertDialog.Builder(MainActivity.this)
                        .setTitle("อัปเดตไม่สำเร็จ")
                        .setMessage(msg)
                        .setPositiveButton("ตกลง", null)
                        .show();
                });
                if (apk != null) apk.delete();
            }
        }, "stable-ip-updater").start();
    }

    private String readLimited(InputStream in, int maxBytes) throws IOException {
        try (InputStream input = in;
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int n;
            int total = 0;
            while ((n = input.read(buffer)) != -1) {
                total += n;
                if (total > maxBytes) {
                    throw new IOException("ข้อมูลจากเซิร์ฟเวอร์ใหญ่เกินกำหนด");
                }
                output.write(buffer, 0, n);
            }
            return output.toString("UTF-8");
        }
    }

    private void installDownloadedApk(File apk) {
        if (apk == null || !apk.isFile()) {
            Toast.makeText(this, "ไม่พบไฟล์อัปเดต", Toast.LENGTH_LONG).show();
            return;
        }

        if (Build.VERSION.SDK_INT >= 26
                && !getPackageManager().canRequestPackageInstalls()) {
            downloadedUpdate = apk;
            new AlertDialog.Builder(this)
                .setTitle("อนุญาตติดตั้งอัปเดต")
                .setMessage(
                    "Android ต้องให้คุณอนุญาตติดตั้งแอปจาก Stable IP Finder AI " +
                    "ก่อน จากนั้นกลับมาที่แอปเพื่อเปิดหน้าติดตั้งอีกครั้ง"
                )
                .setNegativeButton("ยกเลิก", null)
                .setPositiveButton("เปิดการตั้งค่า", (dialog, which) -> {
                    Intent settings = new Intent(
                        Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:" + getPackageName())
                    );
                    startActivityForResult(settings, 7104);
                })
                .show();
            return;
        }
        launchInstaller(apk);
    }

    private void launchInstaller(File apk) {
        try {
            Uri uri = FileProvider.getUriForFile(
                this, getPackageName() + ".fileprovider", apk
            );
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(
                uri, "application/vnd.android.package-archive"
            );
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(
                this, "เปิดตัวติดตั้งไม่ได้: " + e.getMessage(),
                Toast.LENGTH_LONG
            ).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 7104 && downloadedUpdate != null) {
            if (Build.VERSION.SDK_INT < 26
                    || getPackageManager().canRequestPackageInstalls()) {
                launchInstaller(downloadedUpdate);
            } else {
                Toast.makeText(
                    this, "ยังไม่ได้อนุญาตติดตั้งจากแอปนี้",
                    Toast.LENGTH_LONG
                ).show();
            }
        }
    }

    private void runScan(long net, int prefix, int[] ports, long count) {
        scanning = true;
        runOnUiThread(() -> {
            scanButton.setEnabled(false);
            resultText.setText("กำลังเริ่มทดสอบ TCP...");
        });

        StringBuilder log = new StringBuilder();
        List<Stat> stats = new ArrayList<>();
        long start = net;
        long end = net + count - 1;
        if (prefix <= 30) {
            start++;
            end--;
        }

        try {
            for (long addr = start; addr <= end; addr++) {
                String host = toIPv4(addr);

                for (int port : ports) {
                    Stat stat = new Stat();
                    stat.ip = host;
                    stat.port = port;

                    for (int round = 1; round <= ROUNDS; round++) {
                        long t0 = System.nanoTime();
                        boolean ok = false;
                        try (Socket socket = new Socket()) {
                            socket.connect(
                                new InetSocketAddress(host, port),
                                CONNECT_TIMEOUT_MS
                            );
                            ok = true;
                        } catch (IOException ignored) {
                            // ปิดพอร์ต/timeout/ไม่สามารถเชื่อมต่อ
                        }

                        long ms = (System.nanoTime() - t0) / 1_000_000L;
                        if (ok) {
                            stat.ok++;
                            stat.totalMs += ms;
                            stat.bestMs = Math.min(stat.bestMs, ms);
                        }

                        try {
                            Thread.sleep(RATE_LIMIT_MS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                    stats.add(stat);
                }

                final int done = (int)(addr - start + 1);
                final int total = (int)(end - start + 1);
                runOnUiThread(() -> resultText.setText(
                    "กำลังทดสอบ IP " + done + "/" + total +
                    "\nแต่ละ IP และพอร์ตทดสอบ " + ROUNDS + " รอบ"
                ));
            }

            stats.sort((a, b) -> {
                int aa = Integer.compare(b.ok, a.ok);
                if (aa != 0) return aa;
                return Double.compare(a.avg(), b.avg());
            });

            log.append("ผลทดสอบ TCP\n");
            log.append("ช่วง: ").append(toIPv4(net))
                .append("/").append(prefix).append("\n");
            log.append("รอบต่อ IP/พอร์ต: ").append(ROUNDS).append("\n");
            log.append("หมายเหตุ: TCP connect ไม่ใช่ ICMP Ping\n\n");

            int shown = Math.min(3, stats.size());
            log.append("TOP ").append(shown).append("\n");
            for (int i = 0; i < shown; i++) {
                Stat s = stats.get(i);
                log.append(i + 1).append(". ")
                    .append(s.ip).append(":").append(s.port)
                    .append(" | สำเร็จ ").append(s.ok)
                    .append("/").append(ROUNDS)
                    .append(" | เฉลี่ยสำเร็จ ");
                if (s.ok == 0) {
                    log.append("ไม่มีข้อมูล");
                } else {
                    log.append(String.format(Locale.US, "%.1f ms", s.avg()));
                }
                log.append("\n");
            }

            log.append("\nผลทั้งหมด\n");
            for (Stat s : stats) {
                log.append(s.ip).append(":").append(s.port)
                    .append(" | ").append(s.ok).append("/")
                    .append(ROUNDS).append(" | ");
                if (s.ok == 0) log.append("เชื่อมต่อไม่สำเร็จ");
                else log.append(String.format(Locale.US,
                    "เฉลี่ย %.1f ms, ดีที่สุด %d ms",
                    s.avg(), s.bestMs));
                log.append("\n");
            }
        } catch (Exception e) {
            log.append("\nหยุดเพราะข้อผิดพลาด: ").append(e.getMessage());
        } finally {
            scanning = false;
            final String output = log.toString();
            runOnUiThread(() -> {
                resultText.setText(output.isEmpty() ?
                    "ไม่มีผลทดสอบ" : output);
                scanButton.setEnabled(true);
            });
        }
    }
}
