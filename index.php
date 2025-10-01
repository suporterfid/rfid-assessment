<?php
/*******************************************************
 * RFID Sorter Assessment – PHP + SQLite (single-file app)
 * Recursos:
 * - CRUD de levantamentos (respostas)
 * - Relatórios filtrados por cliente/site/período
 * - Upload de anexos (imagens, PDFs)
 * - Login/logout (usuários em tabela users)
 * - API REST /api/responses (autenticação via token)
 * - Sugestões automáticas da OpenAI (botão "Sugerir IA")
 *******************************************************/

declare(strict_types=1);
ini_set('display_errors', '1');
error_reporting(E_ALL);

session_start();

const DB_FILE = __DIR__ . '/data.db';
const APP_TITLE = 'RFID Sorter Assessment';
const ENABLE_QUESTION_ADMIN = true;

// ---------- DB ----------
function db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $pdo = new PDO('sqlite:' . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    migrate($pdo);
    return $pdo;
}

function migrate(PDO $pdo): void {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            section_id INTEGER NOT NULL,
            key_name TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            type TEXT NOT NULL,
            options TEXT,
            required INTEGER NOT NULL DEFAULT 0,
            sort_order INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(section_id) REFERENCES sections(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            client_name TEXT,
            site_location TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS response_values (
            response_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            value TEXT,
            PRIMARY KEY(response_id, question_id),
            FOREIGN KEY(response_id) REFERENCES responses(id) ON DELETE CASCADE,
            FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            api_token TEXT
        );
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            response_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(response_id) REFERENCES responses(id) ON DELETE CASCADE
        );
    ");

    // Seed admin user
    $has = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    if ($has === 0) {
        $hash = password_hash('admin', PASSWORD_BCRYPT);
        $token = bin2hex(random_bytes(16));
        $pdo->prepare("INSERT INTO users (username,password_hash,api_token) VALUES (?,?,?)")
            ->execute(['admin', $hash, $token]);
    }

    // Seed básico de perguntas se vazio
    $hasSec = (int)$pdo->query("SELECT COUNT(*) FROM sections")->fetchColumn();
    if ($hasSec === 0) {
        seedSurvey($pdo);
    }
}

// ---------- Seed Survey ----------
function seedSurvey(PDO $pdo): void {
    $sections = [
        ['Informações Fundamentais – Físico & Layout', 10],
        ['Produtos & Embalagens', 20],
        ['Sistema de Controle & Automação', 30]
    ];
    $pdo->beginTransaction();
    $stmtSec = $pdo->prepare("INSERT INTO sections (name, sort_order) VALUES (?, ?)");
    $stmtQ = $pdo->prepare("INSERT INTO questions (section_id, key_name, label, type, options, required, sort_order) VALUES (?,?,?,?,?,?,?)");

    $secIds = [];
    foreach ($sections as [$name, $order]) {
        $stmtSec->execute([$name, $order]);
        $secIds[$name] = $pdo->lastInsertId();
    }
    $stmtQ->execute([$secIds['Informações Fundamentais – Físico & Layout'], 'layout_tipo', 'Layout geral', 'text', null, 0, 0]);
    $stmtQ->execute([$secIds['Produtos & Embalagens'], 'peso_medio', 'Peso médio (kg)', 'number', null, 0, 0]);

    $pdo->commit();
}

// ---------- Helpers ----------
function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function nowIso(): string { return (new DateTime('now'))->format('c'); }
function redirect(string $to): never { header("Location: $to"); exit; }

// ---------- Auth ----------
function currentUser(): ?array {
    if (!isset($_SESSION['uid'])) return null;
    $st = db()->prepare("SELECT * FROM users WHERE id=?"); $st->execute([$_SESSION['uid']]);
    return $st->fetch(PDO::FETCH_ASSOC) ?: null;
}
function requireLogin(): void {
    if (!currentUser()) redirect("?action=login");
}

// ---------- Routing ----------
$action = $_GET['action'] ?? 'home';
$pdo = db();

// ---------- API REST ----------
if (str_starts_with($_SERVER['REQUEST_URI'], '/api/')) {
    header('Content-Type: application/json; charset=utf-8');
    $token = $_GET['token'] ?? '';
    $usr = $pdo->prepare("SELECT * FROM users WHERE api_token=?"); $usr->execute([$token]); $usr = $usr->fetch();
    if (!$usr) { http_response_code(401); echo json_encode(['error'=>'invalid token']); exit; }
    $path = explode('/', trim($_SERVER['REQUEST_URI'], '/'));
    if ($path[1] === 'responses') {
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            if (isset($path[2])) {
                $id = (int)$path[2];
                $r = getResponse($pdo, $id);
                echo json_encode($r + ['values'=>getResponseValues($pdo,$id)]);
            } else {
                $rs = $pdo->query("SELECT * FROM responses")->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode($rs);
            }
        }
    }
    exit;
}

// ---------- CRUD Helpers ----------
function getResponse(PDO $pdo, int $id): ?array {
    $st=$pdo->prepare("SELECT * FROM responses WHERE id=?"); $st->execute([$id]);
    return $st->fetch(PDO::FETCH_ASSOC) ?: null;
}
function getResponseValues(PDO $pdo, int $id): array {
    $st=$pdo->prepare("SELECT q.key_name,v.value FROM response_values v JOIN questions q ON q.id=v.question_id WHERE response_id=?");
    $st->execute([$id]); $map=[];
    foreach($st->fetchAll(PDO::FETCH_ASSOC) as $r) $map[$r['key_name']]=$r['value'];
    return $map;
}

// ---------- Upload ----------
if ($action==='upload_attachment' && $_SERVER['REQUEST_METHOD']==='POST') {
    requireLogin();
    $rid=(int)$_POST['response_id'];
    if (!empty($_FILES['file']['name'])) {
        $dir=__DIR__.'/uploads'; if (!is_dir($dir)) mkdir($dir,0777,true);
        $fname=uniqid().'_'.basename($_FILES['file']['name']);
        move_uploaded_file($_FILES['file']['tmp_name'],$dir.'/'.$fname);
        $pdo->prepare("INSERT INTO attachments (response_id,filename,original_name,uploaded_at) VALUES (?,?,?,?)")
            ->execute([$rid,$fname,$_FILES['file']['name'],nowIso()]);
    }
    redirect("?action=view_response&id=$rid");
}

// ---------- Relatórios ----------
function page_reports(PDO $pdo): void {
    requireLogin();
    $client=$_GET['client']??''; $site=$_GET['site']??''; $from=$_GET['from']??''; $to=$_GET['to']??'';
    $sql="SELECT * FROM responses WHERE 1=1"; $p=[];
    if($client){$sql.=" AND client_name LIKE ?";$p[]="%$client%";}
    if($site){$sql.=" AND site_location LIKE ?";$p[]="%$site%";}
    if($from){$sql.=" AND date(created_at)>=date(?)";$p[]=$from;}
    if($to){$sql.=" AND date(created_at)<=date(?)";$p[]=$to;}
    $st=$pdo->prepare($sql);$st->execute($p);$rows=$st->fetchAll(PDO::FETCH_ASSOC);

    ob_start(); ?>
    <h1 class="h4 mb-3">Relatórios</h1>
    <form method="get" class="row g-2 mb-3">
      <input type="hidden" name="action" value="reports">
      <div class="col"><input name="client" value="<?=h($client)?>" class="form-control" placeholder="Cliente"></div>
      <div class="col"><input name="site" value="<?=h($site)?>" class="form-control" placeholder="Site"></div>
      <div class="col"><input type="date" name="from" value="<?=h($from)?>" class="form-control"></div>
      <div class="col"><input type="date" name="to" value="<?=h($to)?>" class="form-control"></div>
      <div class="col"><button class="btn btn-primary">Filtrar</button></div>
    </form>
    <div class="bg-white p-3 rounded shadow-sm">
      <table class="table table-sm">
        <thead><tr><th>ID</th><th>Título</th><th>Cliente</th><th>Local</th><th>Criado</th></tr></thead>
        <tbody>
        <?php foreach($rows as $r): ?>
          <tr><td><?=$r['id']?></td><td><?=h($r['title'])?></td><td><?=h($r['client_name'])?></td><td><?=h($r['site_location'])?></td><td><?=$r['created_at']?></td></tr>
        <?php endforeach;?>
        </tbody>
      </table>
    </div>
    <?php layout(ob_get_clean(),"Relatórios – ".APP_TITLE);
}

// ---------- Layout ----------
function layout(string $content,string $title=APP_TITLE):void{
    $u=currentUser();
    echo "<!doctype html><html><head><meta charset='utf-8'><title>".h($title)."</title>
    <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'></head><body>
    <nav class='navbar navbar-dark bg-dark navbar-expand'><div class='container'>
      <a class='navbar-brand' href='?'>".APP_TITLE."</a>
      <div class='navbar-nav'>
        <a class='nav-link' href='?action=list_responses'>Respostas</a>
        <a class='nav-link' href='?action=reports'>Relatórios</a>";
    if($u){ echo "<a class='nav-link' href='?action=logout'>Logout (".h($u['username']).")</a>"; }
    else { echo "<a class='nav-link' href='?action=login'>Login</a>"; }
    echo "</div></div></nav><main class='container py-4'>{$content}</main>
    <script>
    async function fetchAiSuggestion(prompt, btn){
      btn.disabled = true; btn.textContent='Consultando...';
      try {
        const form = btn.closest('form');
        const formData = new FormData(form);
        const context = {};
        for (const [k,v] of formData.entries()) {
          if (k.startsWith('q[')) {
            const field = k.slice(2, -1);
            context[field] = v;
          }
        }
        const res = await fetch('ai.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt, context })
        });
        const data = await res.json();
        const input = btn.closest('.input-group').querySelector('input,textarea');
        if (data.suggestion) input.value = data.suggestion;
      } catch (e) {
        alert('Erro ao consultar IA: ' + e);
      }
      btn.disabled = false; btn.textContent='Sugerir IA';
    }
    </script>
    </body></html>";
}

// ---------- Pages ----------
function page_home():void{ ob_start(); ?>
  <div class="bg-white p-4 rounded shadow-sm">
    <h1 class="h4 mb-3">Bem-vindo</h1>
    <p>Use este app para cadastrar levantamentos de sorter com RFID.</p>
  </div>
<?php layout(ob_get_clean()); }

function page_login(string $error=''):void{ ob_start(); ?>
  <div class="bg-white p-4 rounded shadow-sm" style="max-width:400px;margin:auto;">
    <h1 class="h4 mb-3">Login</h1>
    <?php if($error): ?><div class="alert alert-danger"><?=$error?></div><?php endif;?>
    <form method="post" action="?action=login">
      <div class="mb-3"><input name="username" class="form-control" placeholder="Usuário"></div>
      <div class="mb-3"><input type="password" name="password" class="form-control" placeholder="Senha"></div>
      <button class="btn btn-primary">Entrar</button>
    </form>
  </div>
<?php layout(ob_get_clean(),"Login"); }

// ---------- Dispatch ----------
if($action==='login' && $_SERVER['REQUEST_METHOD']==='POST'){
    $u=$_POST['username']; $p=$_POST['password'];
    $st=$pdo->prepare("SELECT * FROM users WHERE username=?");$st->execute([$u]);$usr=$st->fetch();
    if($usr && password_verify($p,$usr['password_hash'])){$_SESSION['uid']=$usr['id'];redirect("?");}
    else{ page_login("Usuário/senha inválidos"); }
}
elseif($action==='login'){ page_login(); }
elseif($action==='logout'){ session_destroy(); redirect("?"); }
elseif($action==='reports'){ page_reports($pdo); }
else { page_home(); }
