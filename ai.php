<?php
// ai.php – endpoint para sugestões da OpenAI (contextualizado)

header('Content-Type: application/json; charset=utf-8');

session_start();
$hasUser = isset($_SESSION['uid']);
$hasGuest = isset($_SESSION['guest_email']);
if (!$hasUser && !$hasGuest) {
    http_response_code(401);
    echo json_encode(['error' => 'Não autenticado']);
    exit;
}

$input = json_decode(file_get_contents("php://input"), true);
$prompt = $input['prompt'] ?? '';
$context = $input['context'] ?? []; // dados já preenchidos
if (!$prompt) {
    http_response_code(400);
    echo json_encode(['error' => 'Prompt vazio']);
    exit;
}

$apiKey = getenv("OPENAI_API_KEY");
if (!$apiKey) {
    $apiKey = ini_get('openai_api_key');
}
if (!$apiKey) {
    $apiKey = $_ENV['OPENAI_API_KEY'] ?? $_SERVER['OPENAI_API_KEY'] ?? null;
}
if (is_string($apiKey)) {
    $apiKey = trim($apiKey);
}
if (!$apiKey) {
    http_response_code(500);
    echo json_encode(['error' => 'OPENAI_API_KEY não definido']);
    exit;
}

// Monta contexto em texto
$ctxText = "";
if ($context && is_array($context)) {
    $ctxText .= "Dados já informados no levantamento:\n";
    foreach ($context as $k => $v) {
        if ($v !== "") $ctxText .= "- $k: $v\n";
    }
    $ctxText .= "\n";
}

// Chamada à OpenAI
$ch = curl_init("https://api.openai.com/v1/chat/completions");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Content-Type: application/json",
    "Authorization: Bearer $apiKey"
]);

$data = [
    "model" => "gpt-4o-mini",
    "messages" => [
        ["role" => "system", "content" => "Você é um engenheiro de RFID ajudando a preencher um levantamento de sorter. Sugira valores realistas, mas o usuário sempre deve revisar antes de salvar."],
        ["role" => "user", "content" => $ctxText . "Pergunta: " . $prompt]
    ],
    "temperature" => 0.4,
    "max_tokens" => 250
];

curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
$res = curl_exec($ch);

if ($res === false) {
    http_response_code(500);
    echo json_encode(['error' => curl_error($ch)]);
    exit;
}

$decoded = json_decode($res, true);
$suggestion = $decoded['choices'][0]['message']['content'] ?? 'Sem sugestão';

echo json_encode(['suggestion' => trim($suggestion)], JSON_UNESCAPED_UNICODE);
