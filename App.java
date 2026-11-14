package pnm;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.config.annotation.*;

@SpringBootApplication
@RestController
public class App {
    static final Path DB = Path.of("db"), DATA = Path.of("data");
    static final ObjectMapper M = new ObjectMapper();
    static final Path USERS = DB.resolve("users.json"), FILES = DB.resolve("PNM_All_files.json"), FOLDERS = DB.resolve("folders.json");
    static final String PWD_RULE = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,}$";
    static final DateTimeFormatter DMY = DateTimeFormatter.ofPattern("dd/MM/yyyy"), TS = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
    static final String LOGO = "<svg width='80' height='80' viewBox='0 0 100 100'><circle cx='50' cy='50' r='46' fill='#b45309'/><text x='50' y='62' font-size='34' text-anchor='middle' fill='#fff' font-family='serif'>PNM</text></svg>";

    public static void main(String[] a) throws Exception {
        Files.createDirectories(DB); Files.createDirectories(DATA);
        if (!Files.exists(FOLDERS)) {
            List<String> f = List.of("Aagam Vani", "Tantra Vani", "Pratibha Smruti", "Shakti Suyash", "Khushwakt Rai ji");
            M.writeValue(FOLDERS.toFile(), f);
            for (String x : f) Files.createDirectories(DATA.resolve(x));
        }
        if (!Files.exists(FILES)) M.writeValue(FILES.toFile(), new ArrayList<>());
        if (!Files.exists(USERS)) {
            List<Map<String, String>> u = new ArrayList<>();
            u.add(user("Admin", "Admin@027", "Admin", "Pratibha_GLM", "24/03/1980"));
            M.writeValue(USERS.toFile(), u);
        }
        System.setProperty("server.port", System.getenv().getOrDefault("PORT", "8080"));
        SpringApplication.run(App.class, a);
    }

    // ---------- helpers ----------
    static Map<String, String> user(String n, String p, String role, String hint, String dob) {
        Map<String, String> m = new LinkedHashMap<>();
        String now = LocalDate.now().format(DMY);
        m.put("username", n); m.put("password", hash(p)); m.put("role", role); m.put("status", "A");
        m.put("password_hint", hint); m.put("Date_Of_Birth", dob);
        m.put("PNM_Code", hash("PNM@027" + dob.replace("/", "")));
        m.put("created_date", now); m.put("last_updated_date", now);
        return m;
    }
    static String hash(String s) {
        try {
            byte[] salt = new byte[16]; new SecureRandom().nextBytes(salt);
            return Base64.getEncoder().encodeToString(salt) + ":" + pbk(s, salt);
        } catch (Exception e) { throw new RuntimeException(e); }
    }
    static String pbk(String s, byte[] salt) throws Exception {
        return Base64.getEncoder().encodeToString(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(new PBEKeySpec(s.toCharArray(), salt, 120000, 256)).getEncoded());
    }
    static boolean check(String s, String stored) {
        try { String[] p = stored.split(":"); return pbk(s, Base64.getDecoder().decode(p[0])).equals(p[1]); }
        catch (Exception e) { return false; }
    }
    static synchronized List<Map<String, String>> rows(Path p) throws Exception {
        return M.readValue(p.toFile(), new TypeReference<>() {});
    }
    static synchronized void save(Path p, Object o) throws Exception { M.writerWithDefaultPrettyPrinter().writeValue(p.toFile(), o); }
    static List<String> folders() throws Exception { return M.readValue(FOLDERS.toFile(), new TypeReference<>() {}); }
    static String esc(String s) { return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;"); }
    static String enc(String s) { return URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20"); }
    static ResponseEntity<String> ok(String t, String body) {
        String h = "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><title>" + t + "</title><style>"
            + "body{font-family:sans-serif;max-width:760px;margin:auto;padding:16px;background:#fff8ee}.c{background:#fff;border-radius:10px;padding:14px;margin:10px 0;box-shadow:0 1px 4px #0003}"
            + "input,select,button{padding:8px;margin:4px 0;width:100%;box-sizing:border-box}button,.b{background:#b45309;color:#fff;border:0;border-radius:6px;cursor:pointer;width:auto;padding:8px 14px;text-decoration:none;display:inline-block}"
            + ".e{color:#b00}nav{margin-top:24px;padding-top:10px;border-top:1px solid #ccc}nav a{margin-right:14px}</style>"
            + "<div style='text-align:center'>" + LOGO + "<h2>PNM Stuti Library</h2></div>" + body;
        return ResponseEntity.ok().contentType(MediaType.valueOf("text/html;charset=UTF-8")).body(h);
    }
    static ResponseEntity<String> go(String u) { return ResponseEntity.status(302).header("Location", u).build(); }
    static String role(HttpSession s) { return (String) s.getAttribute("r"); }
    static boolean is(HttpSession s, String... r) { return Arrays.asList(r).contains(role(s)); }
    static String msg(String m) { return m == null ? "" : "<p class=e>" + esc(m) + "</p>"; }
    static ResponseEntity<String> deny() { return ok("Denied", "<p class=e>Access denied.</p><a href='/home'>Back</a>"); }
    static String folderSelect() throws Exception {
        StringBuilder b = new StringBuilder("<select name=folder>");
        for (String f : folders()) b.append("<option>").append(esc(f)).append("</option>");
        return b.append("</select>").toString();
    }

    // ---------- auth ----------
    @GetMapping("/") public ResponseEntity<String> root() { return go("/home"); }

    @GetMapping("/login") public ResponseEntity<String> loginPage(@RequestParam(required = false) String m) {
        return ok("Login", "<div class=c>" + msg(m) + "<form method=post action=/login>Username<input name=u required>Password<input type=password name=p required>"
            + "<button>Login</button></form><p><a href='/reset'>Reset Password</a></p></div>");
    }
    @PostMapping("/login") public ResponseEntity<String> login(@RequestParam String u, @RequestParam String p, HttpSession s) throws Exception {
        for (var r : rows(USERS))
            if (r.get("username").equals(u) && "A".equals(r.get("status")) && check(p, r.get("password"))) {
                s.setAttribute("u", u); s.setAttribute("r", r.get("role")); s.setMaxInactiveInterval(3600);
                return go("/home");
            }
        return go("/login?m=" + enc("Wrong username/password"));
    }
    @GetMapping("/logout") public ResponseEntity<String> logout(HttpSession s) { s.invalidate(); return go("/login"); }

    // ---------- home / playback ----------
    @GetMapping("/home") public ResponseEntity<String> home(HttpSession s) throws Exception {
        StringBuilder b = new StringBuilder("<p>Hello <b>" + esc((String) s.getAttribute("u")) + "</b> (" + role(s) + ")</p>");
        for (String f : folders())
            b.append("<div class=c><a href='/folder?f=").append(enc(f)).append("'><b>").append(esc(f)).append("</b></a> &nbsp; ")
             .append("<a class=b href='/playall?f=").append(enc(f)).append("'>Play All Stuti</a></div>");
        b.append("<nav>");
        if (is(s, "Admin")) b.append("<a href='/admin'>Admin</a>");
        if (is(s, "Admin", "Contributor")) b.append("<a href='/upload'>Upload file</a>");
        b.append("<a href='/reset'>Reset Password</a><a href='/logout'>Logout</a></nav>");
        return ok("Home", b.toString());
    }
    @GetMapping("/folder") public ResponseEntity<String> folder(@RequestParam String f) throws Exception {
        StringBuilder b = new StringBuilder("<h3>" + esc(f) + "</h3>");
        for (var r : rows(FILES))
            if (r.get("Folder_Name").equals(f) && "A".equals(r.get("Status")))
                b.append("<div class=c><a href='/play?f=").append(enc(f)).append("&n=").append(enc(r.get("File_name"))).append("'>").append(esc(r.get("File_Title"))).append("</a></div>");
        return ok(f, b + "<a href='/home'>Back</a>");
    }
    @GetMapping("/play") public ResponseEntity<String> play(@RequestParam String f, @RequestParam String n) {
        return ok("Play", "<h3>" + esc(n) + "</h3><video controls autoplay style='width:100%' src='/media/" + enc(f) + "/" + enc(n) + "'></video><p><a href='/folder?f=" + enc(f) + "'>Back</a></p>");
    }
    @GetMapping("/playall") public ResponseEntity<String> playAll(@RequestParam String f) throws Exception {
        List<String> l = new ArrayList<>();
        for (var r : rows(FILES)) if (r.get("Folder_Name").equals(f) && "A".equals(r.get("Status"))) l.add("/media/" + enc(f) + "/" + enc(r.get("File_name")));
        return ok("Play All", "<h3>" + esc(f) + " - Play All</h3><video id=v controls autoplay style='width:100%'></video><p id=t></p><script>const L=" + M.writeValueAsString(l)
            + ";let i=0;const v=document.getElementById('v');function go(){if(i<L.length){v.src=L[i];document.getElementById('t').textContent=(i+1)+' / '+L.length;v.play();}}"
            + "v.onended=()=>{i++;go()};if(L.length)go();else document.getElementById('t').textContent='No files.';</script><p><a href='/home'>Back</a></p>");
    }

    // ---------- upload (Admin + Contributor) ----------
    @GetMapping("/upload") public ResponseEntity<String> uploadPage(HttpSession s, @RequestParam(required = false) String m) throws Exception {
        if (!is(s, "Admin", "Contributor")) return deny();
        return ok("Upload", "<div class=c>" + msg(m) + "<form method=post action=/upload enctype=multipart/form-data>Folder" + folderSelect()
            + "File title<input name=title required>Status<select name=status><option>A</option><option>I</option></select><input type=file name=file accept='audio/*,video/*' required>"
            + "<button>Upload</button></form></div><a href='/home'>Back</a>");
    }
    @PostMapping("/upload") public ResponseEntity<String> upload(HttpSession s, @RequestParam String folder, @RequestParam String title, @RequestParam String status, @RequestParam MultipartFile file) throws Exception {
        if (!is(s, "Admin", "Contributor")) return deny();
        if (!folders().contains(folder)) return go("/upload?m=" + enc("Invalid folder"));
        String name = Path.of(Objects.requireNonNull(file.getOriginalFilename())).getFileName().toString();
        Path dest = DATA.resolve(folder).resolve(name);
        if (Files.exists(dest) && !is(s, "Admin")) return go("/upload?m=" + enc("File already exists (contributors cannot overwrite)"));
        Files.createDirectories(dest.getParent());
        file.transferTo(dest.toAbsolutePath());
        var all = rows(FILES);
        Map<String, String> r = new LinkedHashMap<>();
        r.put("Folder_Name", folder); r.put("File_Title", title); r.put("File_name", name); r.put("Status", "I".equals(status) ? "I" : "A");
        all.add(r); save(FILES, all);
        return go("/upload?m=" + enc("Uploaded: " + name));
    }

    // ---------- admin ----------
    @GetMapping("/admin") public ResponseEntity<String> admin(HttpSession s, @RequestParam(required = false) String m) throws Exception {
        if (!is(s, "Admin")) return deny();
        StringBuilder b = new StringBuilder(msg(m));
        b.append("<div class=c><h3>Create user</h3><form method=post action=/admin/user>Username<input name=u required>Password<input type=password name=p required>"
            + "Date of birth<input type=date name=dob required>Role<select name=role><option>Admin</option><option>Contributor</option><option>General</option></select>"
            + "Password hint<input name=hint required><button>Create</button></form></div>");
        b.append("<div class=c><h3>Change user password</h3><form method=post action=/admin/pwd>Username<input name=u required>New password<input type=password name=p required><button>Change</button></form></div>");
        b.append("<div class=c><h3>Create folder</h3><form method=post action=/admin/folder><input name=name required><button>Create</button></form></div>");
        b.append("<div class=c><h3>Add / update PNM_All_files row</h3><form method=post action=/admin/row>Folder").append(folderSelect())
         .append("File title<input name=title required>File name (must match uploaded file)<input name=fname required>Status<select name=status><option>A</option><option>I</option></select><button>Save row</button></form></div>");
        b.append("<div class=c><h3>Current rows</h3>");
        for (var r : rows(FILES)) b.append(esc(r.get("Folder_Name")) + " | " + esc(r.get("File_Title")) + " | " + esc(r.get("File_name")) + " | " + esc(r.get("Status")) + "<br>");
        return ok("Admin", b + "</div><a href='/upload'>Upload file</a> &nbsp; <a href='/home'>Back</a>");
    }
    @PostMapping("/admin/user") public ResponseEntity<String> addUser(HttpSession s, @RequestParam String u, @RequestParam String p, @RequestParam String dob, @RequestParam String role, @RequestParam String hint) throws Exception {
        if (!is(s, "Admin")) return deny();
        var all = rows(USERS);
        if (all.stream().anyMatch(r -> r.get("username").equalsIgnoreCase(u))) return go("/admin?m=" + enc("Username already exists"));
        if (!p.matches(PWD_RULE)) return go("/admin?m=" + enc("Password needs 8+ chars, upper, lower, number, special"));
        if (!List.of("Admin", "Contributor", "General").contains(role)) return go("/admin?m=" + enc("Bad role"));
        all.add(user(u, p, role, hint, LocalDate.parse(dob).format(DMY))); save(USERS, all);
        return go("/admin?m=" + enc("User created"));
    }
    @PostMapping("/admin/pwd") public ResponseEntity<String> adminPwd(HttpSession s, @RequestParam String u, @RequestParam String p) throws Exception {
        if (!is(s, "Admin")) return deny();
        if (!p.matches(PWD_RULE)) return go("/admin?m=" + enc("Weak password"));
        var all = rows(USERS);
        for (var r : all) if (r.get("username").equals(u)) { r.put("password", hash(p)); r.put("last_updated_date", LocalDate.now().format(DMY)); save(USERS, all); return go("/admin?m=" + enc("Password changed")); }
        return go("/admin?m=" + enc("User not found"));
    }
    @PostMapping("/admin/folder") public ResponseEntity<String> addFolder(HttpSession s, @RequestParam String name) throws Exception {
        if (!is(s, "Admin")) return deny();
        name = name.trim();
        if (!name.matches("[\\w .-]+")) return go("/admin?m=" + enc("Invalid folder name"));
        var f = new ArrayList<>(folders());
        if (!f.contains(name)) { f.add(name); save(FOLDERS, f); Files.createDirectories(DATA.resolve(name)); }
        return go("/admin?m=" + enc("Folder ready"));
    }
    @PostMapping("/admin/row") public ResponseEntity<String> row(HttpSession s, @RequestParam String folder, @RequestParam String title, @RequestParam String fname, @RequestParam String status) throws Exception {
        if (!is(s, "Admin")) return deny();
        var all = rows(FILES);
        for (var r : all) if (r.get("Folder_Name").equals(folder) && r.get("File_name").equals(fname)) { r.put("File_Title", title); r.put("Status", status); save(FILES, all); return go("/admin?m=" + enc("Row updated")); }
        Map<String, String> r = new LinkedHashMap<>();
        r.put("Folder_Name", folder); r.put("File_Title", title); r.put("File_name", fname); r.put("Status", status);
        all.add(r); save(FILES, all);
        return go("/admin?m=" + enc("Row added"));
    }

    // ---------- reset password (public) ----------
    @GetMapping("/reset") public ResponseEntity<String> resetPage(@RequestParam(required = false) String m) {
        return ok("Reset", "<div class=c>" + msg(m) + "<form method=post action=/reset>Username<input name=u required>Date of birth<input type=date name=dob required>Password hint<input name=hint required>"
            + "PNM code<input name=pnm required>New password<input type=password name=p required>Re-enter password<input type=password name=p2 required><button>Reset</button></form>"
            + "<p>Min 8 chars, 1 capital, 1 small, 1 number, 1 special.</p><a href='/login'>Back</a></div>");
    }
    @PostMapping("/reset") public ResponseEntity<String> reset(@RequestParam String u, @RequestParam String dob, @RequestParam String hint, @RequestParam String pnm, @RequestParam String p, @RequestParam String p2) throws Exception {
        String bad = "/reset?m=" + enc("Details do not match or password invalid");
        if (!p.equals(p2) || !p.matches(PWD_RULE)) return go(bad);
        var all = rows(USERS);
        for (var r : all)
            if (r.get("username").equals(u) && "A".equals(r.get("status")) && r.get("Date_Of_Birth").equals(LocalDate.parse(dob).format(DMY))
                && r.get("password_hint").equals(hint) && check(pnm, r.get("PNM_Code"))) {
                r.put("password", hash(p)); r.put("last_updated_date", LocalDate.now().format(DMY)); save(USERS, all);
                return go("/login?m=" + enc("Password changed. Please login."));
            }
        return go(bad);
    }

    // ---------- login guard + media serving ----------
    @Configuration
    static class Web implements WebMvcConfigurer {
        @Override public void addInterceptors(InterceptorRegistry r) {
            r.addInterceptor(new org.springframework.web.servlet.HandlerInterceptor() {
                @Override public boolean preHandle(jakarta.servlet.http.HttpServletRequest q, jakarta.servlet.http.HttpServletResponse p, Object h) throws Exception {
                    String path = q.getRequestURI();
                    if (path.equals("/login") || path.equals("/reset") || path.equals("/error")) return true;
                    HttpSession s = q.getSession(false);
                    if (s != null && s.getAttribute("u") != null) return true;
                    p.sendRedirect("/login?m=" + enc("Please login (session may have timed out)"));
                    return false;
                }
            });
        }
        @Override public void addResourceHandlers(ResourceHandlerRegistry r) {
            r.addResourceHandler("/media/**").addResourceLocations(DATA.toAbsolutePath().toUri().toString());
        }
    }
}
