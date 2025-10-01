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

$apiKey = ini_get("openai_api_key");

if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool
    {
        return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}

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
            submitter_email TEXT,
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

    // Ensure responses.submitter_email exists for legacy databases
    $cols = $pdo->query("PRAGMA table_info(responses)")->fetchAll(PDO::FETCH_ASSOC);
    $hasSubmitter = false;
    foreach ($cols as $col) {
        if (($col['name'] ?? '') === 'submitter_email') { $hasSubmitter = true; break; }
    }
    if (!$hasSubmitter) {
        $pdo->exec('ALTER TABLE responses ADD COLUMN submitter_email TEXT');
    }

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

    // Garantir que o campo de layout utilize textarea mesmo em bancos antigos
    $pdo->exec("UPDATE questions SET type='textarea' WHERE key_name='layout_tipo' AND type != 'textarea'");
}

// ---------- Seed Survey ----------
function seedSurvey(PDO $pdo): void {
    $sections = [
        ['Características Físicas e Layout', 10],
        ['Produtos & Embalagens', 20],
        ['Sistema de Controle & Automação', 30],
        ['Sistemas de Identificação Atuais', 40],
        ['Infraestrutura Elétrica e de Comunicação', 50],
        ['Integração com Sistemas Corporativos', 60],
        ['Portal de Indução – Reforço ao Código de Barras', 70],
        ['Portais de Saída – Identificação de Dispensação', 80],
        ['Portal de Paletização – Verificação Final', 90],
        ['Perguntas Críticas em Visita Técnica', 100],
        ['Documentos a Solicitar', 110],
        ['Site Survey e Análise RF', 120]
    ];

    $pdo->beginTransaction();
    $stmtSec = $pdo->prepare("INSERT INTO sections (name, sort_order) VALUES (?, ?)");
    $stmtQ = $pdo->prepare("INSERT INTO questions (section_id, key_name, label, type, options, required, sort_order) VALUES (?,?,?,?,?,?,?)");

    $secIds = [];
    foreach ($sections as [$name, $order]) {
        $stmtSec->execute([$name, $order]);
        $secIds[$name] = $pdo->lastInsertId();
    }

    // --- Características Físicas e Layout
    $sid = $secIds['Características Físicas e Layout'];
    $stmtQ->execute([$sid, 'comprimento_total', 'Comprimento total do sorter e seções individuais', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'largura_esteiras', 'Largura das esteiras e espaçamentos entre elas', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'altura_esteiras', 'Altura das esteiras em relação ao piso', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'layout_geral', 'Layout geral (linear, circular, em L ou outras configurações)', 'select', 'linear,circular,L,complexo', 0, 0]);
    $stmtQ->execute([$sid, 'pontos_inducao', 'Pontos de entrada (indução) e número de saídas', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'areas_paletizacao', 'Áreas de paletização e estações de trabalho adjacentes', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'velocidade_operacional', 'Velocidade operacional das esteiras (m/min)', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'variacoes_velocidade', 'Variações de velocidade (picos vs normal)', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'throughput_max', 'Capacidade máxima de throughput (itens/hora)', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'gap_produtos', 'Gaps típicos entre produtos na esteira', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'materiais_construtivos', 'Materiais construtivos', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'estruturas_metais', 'Estruturas metálicas que possam causar interferência RF', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'condicoes_ambiente', 'Condições ambientais (temperatura, umidade, vibração)', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'ruido_eletromag', 'Nível de ruído eletromagnético presente', 'text', null, 0, 0]);

    // --- Produtos & Embalagens
    $sid = $secIds['Produtos & Embalagens'];
    $stmtQ->execute([$sid, 'dimensoes_produtos', 'Dimensões típicas (C x L x A)', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'variacao_tamanhos', 'Variação de tamanhos (menores e maiores)', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'peso_medio', 'Peso médio e variações', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'materiais_embalagens', 'Tipos de materiais das embalagens', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'embalagens_papel_plastico_metal', 'Embalagens de papelão, plástico, metal', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'produtos_liquidos', 'Presença de líquidos ou alto teor de água', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'embalagens_reflexivas', 'Embalagens reflexivas ou metalizadas', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'produtos_empilhados', 'Produtos empilhados/múltiplas camadas', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'num_produtos_simultaneos', 'Número típico de produtos simultâneos na esteira', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'espacamento_minimo', 'Espaçamento mínimo entre produtos consecutivos', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'padrao_agrupamento', 'Padrões de agrupamento (individuais vs lotes)', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'variacao_densidade', 'Variações de densidade em picos', 'text', null, 0, 0]);

    // --- Sistema de Controle & Automação
    $sid = $secIds['Sistema de Controle & Automação'];
    $stmtQ->execute([$sid, 'plc_modelo', 'Marca e modelo do PLC principal', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'protocolos_comunicacao', 'Protocolos de comunicação utilizados', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'scada_existente', 'Sistema SCADA ou interface existente', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'logica_roteamento', 'Lógica atual de roteamento', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'sensores_fotocelulas', 'Fotocélulas para detecção de presença', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'sensores_peso', 'Sensores de peso em estações', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'encoders', 'Encoders para controle de velocidade', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'visao_artificial', 'Sistemas de visão artificial integrados', 'boolean', null, 0, 0]);

    // --- Sistemas de Identificação Atuais
    $sid = $secIds['Sistemas de Identificação Atuais'];
    $stmtQ->execute([$sid, 'localizacao_scanners', 'Localização e quantidade de scanners instalados', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'marcas_modelos_scanners', 'Marcas/modelos e especificações técnicas', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'taxa_leitura_atual', 'Taxa de leitura atual e limitações', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'pontos_problema', 'Pontos problemáticos com baixa taxa de leitura', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'percentual_identificacao', 'Percentual de produtos identificados corretamente', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'intervencoes_manuais', 'Necessidade de intervenções manuais', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'causas_falha', 'Principais causas de falhas de leitura', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'impacto_throughput', 'Impacto no throughput do sistema', 'textarea', null, 0, 0]);

    // --- Infraestrutura Elétrica e de Comunicação
    $sid = $secIds['Infraestrutura Elétrica e de Comunicação'];
    $stmtQ->execute([$sid, 'tensoes_disponiveis', 'Tensões disponíveis', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'capacidade_corrente', 'Capacidade de corrente disponível', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'localizacao_paineis', 'Localização de painéis elétricos e pontos de alimentação', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'sistemas_protecao', 'Sistemas de proteção existentes', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'infra_ethernet', 'Infraestrutura Ethernet disponível e localização de switches', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'largura_banda', 'Largura de banda disponível para RFID', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'protocolos_rede', 'Protocolos de rede suportados', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'seguranca_rede', 'Segurança de rede e políticas de acesso', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'pontos_fixacao', 'Pontos de fixação estrutural para portais RFID', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'acessibilidade_instalacao', 'Acessibilidade para instalação/manutenção', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'restricoes_altura', 'Restrições de altura/largura para montagem', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'interferencias_estruturas', 'Interferências com estruturas existentes', 'textarea', null, 0, 0]);

    // --- Integração com Sistemas Corporativos
    $sid = $secIds['Integração com Sistemas Corporativos'];
    $stmtQ->execute([$sid, 'wms_sistema', 'Sistema WMS/ERP utilizado e versão', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'modulos_implementados', 'Módulos implementados', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'apis_disponiveis', 'APIs disponíveis para integração', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'freq_atualizacoes', 'Frequência de atualizações necessárias', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'estrutura_dados', 'Estrutura de dados de produtos', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'codigos_identificacao', 'Códigos de identificação (EAN, UPC, internos)', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'rastreabilidade_lote', 'Necessidade de rastreabilidade por lote/série', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'requisitos_auditoria', 'Requisitos de auditoria/compliance', 'textarea', null, 0, 0]);

    // --- Portal de Indução
    $sid = $secIds['Portal de Indução – Reforço ao Código de Barras'];
    $stmtQ->execute([$sid, 'falhas_scanner', 'Taxa de falha atual dos scanners', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'tempo_disponivel_leitura', 'Tempo disponível para leitura durante passagem', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'orientacoes_produtos', 'Necessidade de leitura em múltiplas orientações', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'protocolo_falhas', 'Protocolo de tratamento em caso de falha simultânea', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'logica_decisao', 'Lógica de decisão (backup ou simultânea)', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'tempo_resposta', 'Tempo de resposta necessário', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'necessidade_logging', 'Necessidade de logging para auditoria', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'interface_excecoes', 'Interface com sistema de exceções', 'textarea', null, 0, 0]);

    // --- Portais de Saída
    $sid = $secIds['Portais de Saída – Identificação de Dispensação'];
    $stmtQ->execute([$sid, 'num_saidas', 'Número total de saídas/destinos', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'id_saida', 'Identificação única de cada saída', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'criterios_roteamento', 'Critérios de roteamento atuais', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'volume_por_saida', 'Volume de produtos por saída', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'timestamp_dispensacao', 'Necessidade de timestamp por dispensação', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'agrupamento_destino', 'Agrupamento por destino/rota', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'relatorios_automaticos', 'Relatórios automáticos por período', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'integracao_expedicao', 'Integração com sistemas de expedição', 'boolean', null, 0, 0]);

    // --- Portal de Paletização
    $sid = $secIds['Portal de Paletização – Verificação Final'];
    $stmtQ->execute([$sid, 'dimensoes_pallets', 'Dimensões padrão de pallets', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'altura_max_pallet', 'Altura máxima de empilhamento', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'tempo_medio_pallet', 'Tempo médio para formar pallet', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'criterios_completude', 'Critérios de completude', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'comparacao_pedidos', 'Comparação com pedidos originais', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'tolerancias', 'Tolerâncias aceitáveis', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'tratamento_excecoes', 'Processo de tratamento de exceções', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'requisitos_regulatorios', 'Requisitos regulatórios/compliance', 'textarea', null, 0, 0]);

    // --- Perguntas Críticas em Visita Técnica
    $sid = $secIds['Perguntas Críticas em Visita Técnica'];
    $stmtQ->execute([$sid, 'velocidade_max_esteiras', 'Qual a velocidade máxima das esteiras e existe variação durante o dia?', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'produtos_simultaneos_inducao', 'Quantos produtos passam simultaneamente pela indução?', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'gap_min_produtos', 'Qual o gap mínimo entre produtos consecutivos?', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'pontos_acumulo', 'Existem pontos de acúmulo ou filas?', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'taxa_leitura_codigos', 'Qual a taxa de leitura atual dos códigos de barras em cada ponto?', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'motivos_falha', 'Quais os principais motivos de falha na identificação?', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'tratamento_nao_identificados', 'Como o sistema atual trata produtos não identificados?', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'redundancia_identificacao', 'Existe redundância ou backup para falhas de identificação?', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'localizacao_paineis_visita', 'Onde estão localizados os painéis elétricos mais próximos?', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'infra_rede_area', 'Qual a infraestrutura de rede disponível em cada área?', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'restricoes_estrutura', 'Existem restrições para perfuração/soldas na estrutura?', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'interferencias_rf', 'Há interferências RF conhecidas no ambiente?', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'dados_wms', 'Como os dados de identificação são enviados ao WMS atualmente?', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'tempo_resposta_roteamento', 'Qual o tempo de resposta necessário para decisões de roteamento?', 'number', null, 0, 0]);
    $stmtQ->execute([$sid, 'relatorios_necessarios', 'Existem relatórios específicos que precisam ser mantidos?', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'requisitos_auditoria_visita', 'Há requisitos de auditoria ou compliance específicos?', 'boolean', null, 0, 0]);

    // --- Documentos a Solicitar
    $sid = $secIds['Documentos a Solicitar'];
    $stmtQ->execute([$sid, 'diagramas_eletricos', 'Diagramas elétricos e de controle', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'layout_detalhado', 'Layout detalhado com dimensões', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'manual_tecnico', 'Manual técnico do sistema de controle', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'especificacoes_scanners', 'Especificações dos scanners atuais', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'relatorios_performance', 'Relatórios de performance atual', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'estatisticas_throughput', 'Estatísticas de throughput por período', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'registros_manutencao', 'Registros de manutenção e falhas', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'procedimentos_operacionais', 'Procedimentos operacionais padrão', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'documentacao_wms', 'Documentação do WMS/ERP', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'apis_protocolos', 'APIs e protocolos de integração', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'estrutura_banco_dados', 'Estrutura de banco de dados relevante', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'politicas_seguranca_ti', 'Políticas de segurança de TI', 'boolean', null, 0, 0]);

    // --- Site Survey e Análise RF
    $sid = $secIds['Site Survey e Análise RF'];
    $stmtQ->execute([$sid, 'frequencias_utilizadas', 'Frequências utilizadas (902–928 MHz)', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'fontes_interferencia', 'Fontes de interferência RF', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'medicao_ruido', 'Medição de ruído em diferentes horários', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'teste_propagacao', 'Teste de propagação nas áreas', 'textarea', null, 0, 0]);
    $stmtQ->execute([$sid, 'piloto_tags', 'Piloto com tags representativas', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'taxa_leitura_piloto', 'Verificação da taxa de leitura em posições diferentes', 'text', null, 0, 0]);
    $stmtQ->execute([$sid, 'interferencia_multiplos_leitores', 'Interferência entre múltiplos leitores', 'boolean', null, 0, 0]);
    $stmtQ->execute([$sid, 'range_leitura', 'Validação do range de leitura', 'text', null, 0, 0]);

    $pdo->commit();
}


// ---------- Helpers ----------
function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function nowIso(): string { return (new DateTime('now'))->format('c'); }
function redirect(string $to): never { header("Location: $to"); exit; }
function setFlash(string $message): void { $_SESSION['flash'] = $message; }
function popFlash(): ?string {
    if (!isset($_SESSION['flash'])) return null;
    $msg = $_SESSION['flash'];
    unset($_SESSION['flash']);
    return $msg;
}

// ---------- Auth ----------
function currentUser(): ?array {
    if (!isset($_SESSION['uid'])) return null;
    $st = db()->prepare("SELECT * FROM users WHERE id=?"); $st->execute([$_SESSION['uid']]);
    return $st->fetch(PDO::FETCH_ASSOC) ?: null;
}
function requireLogin(): void {
    if (!currentUser()) redirect("?action=login");
}
function requireSurveyAccess(): void {
    if (currentUser() || guestEmail()) {
        return;
    }
    redirect('?action=guest_access');
}
function guestEmail(): ?string {
    return isset($_SESSION['guest_email']) ? (string)$_SESSION['guest_email'] : null;
}
function grantGuestAccess(string $email): void {
    $_SESSION['guest_email'] = $email;
}
function revokeGuestAccess(): void {
    unset($_SESSION['guest_email']);
}

function requireAnyAccess(): void {
    if (currentUser() || guestEmail()) return;
    redirect('?action=guest_access');
}

function actorSubmitterEmail(?array $existingResponse = null): ?string {
    $guest = guestEmail();
    if ($guest) return $guest;
    $user = currentUser();
    if ($user) {
        if ($existingResponse && !empty($existingResponse['submitter_email'])) {
            return $existingResponse['submitter_email'];
        }
        return 'staff:' . ($user['username'] ?? 'usuario');
    }
    return $existingResponse['submitter_email'] ?? null;
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

function fetchSurveyStructure(PDO $pdo): array {
    $sections = $pdo->query("SELECT id, name FROM sections ORDER BY sort_order, id")
        ->fetchAll(PDO::FETCH_ASSOC);
    $stmtQ = $pdo->prepare("SELECT * FROM questions WHERE section_id=? ORDER BY sort_order, id");
    foreach ($sections as &$section) {
        $stmtQ->execute([$section['id']]);
        $section['questions'] = $stmtQ->fetchAll(PDO::FETCH_ASSOC);
    }
    unset($section);
    return $sections;
}

function getAttachments(PDO $pdo, int $responseId): array {
    $st = $pdo->prepare("SELECT id, filename, original_name, uploaded_at FROM attachments WHERE response_id=? ORDER BY datetime(uploaded_at) DESC, id DESC");
    $st->execute([$responseId]);
    return $st->fetchAll(PDO::FETCH_ASSOC);
}

function ensureResponseAccess(PDO $pdo, int $id): array {
    $response = getResponse($pdo, $id);
    if (!$response) {
        setFlash('Resposta não encontrada.');
        redirect('?action=list_responses');
    }
    $user = currentUser();
    if (!$user) {
        $guest = guestEmail();
        if (!$guest || $response['submitter_email'] !== $guest) {
            setFlash('Acesso não autorizado.');
            redirect('?action=list_responses');
        }
    }
    return $response;
}

// ---------- Response Pages ----------
function page_list_responses(PDO $pdo): void {
    requireAnyAccess();
    $user = currentUser();
    $guest = guestEmail();
    $sql = "SELECT id,title,client_name,site_location,submitter_email,created_at,updated_at FROM responses";
    $params = [];
    if (!$user && $guest) {
        $sql .= " WHERE submitter_email = ?";
        $params[] = $guest;
    }
    $sql .= " ORDER BY datetime(updated_at) DESC, id DESC";
    $st = $pdo->prepare($sql);
    $st->execute($params);
    $responses = $st->fetchAll(PDO::FETCH_ASSOC);
    $flash = popFlash();

    ob_start(); ?>
    <div class="d-flex align-items-center justify-content-between mb-3">
      <h1 class="h4 mb-0">Respostas</h1>
      <a class="btn btn-primary" href="?action=new_response">Nova resposta</a>
    </div>
    <?php if($flash): ?><div class="alert alert-success"><?=h($flash)?></div><?php endif; ?>
    <div class="bg-white p-3 rounded shadow-sm">
      <?php if(empty($responses)): ?>
        <p class="mb-0 text-muted">Nenhuma resposta encontrada.</p>
      <?php else: ?>
      <div class="table-responsive">
        <table class="table table-striped align-middle">
          <thead><tr><th>ID</th><th>Título</th><th>Cliente</th><th>Local</th><th>E-mail</th><th>Atualizado</th><th class="text-end">Ações</th></tr></thead>
          <tbody>
          <?php foreach($responses as $response): ?>
            <tr>
              <td><?=$response['id']?></td>
              <td><?=h($response['title'])?></td>
              <td><?=h($response['client_name'])?></td>
              <td><?=h($response['site_location'])?></td>
              <td><?=h($response['submitter_email'])?></td>
              <td><?=h($response['updated_at'])?></td>
              <td class="text-end">
                <a class="btn btn-sm btn-outline-secondary" href="?action=view_response&amp;id=<?=$response['id']?>">Detalhes</a>
                <a class="btn btn-sm btn-outline-primary" href="?action=edit_response&amp;id=<?=$response['id']?>">Editar</a>
                <?php if($user): ?>
                <form method="post" action="?action=delete_response" class="d-inline" onsubmit="return confirm('Excluir resposta #<?=$response['id']?>?');">
                  <input type="hidden" name="id" value="<?=$response['id']?>">
                  <button class="btn btn-sm btn-outline-danger">Excluir</button>
                </form>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>
    </div>
    <?php layout(ob_get_clean(), "Respostas – ".APP_TITLE);
}

function page_response_form(PDO $pdo, ?array $response = null, array $old = [], array $errors = []): void {
    requireAnyAccess();
    $structure = fetchSurveyStructure($pdo);
    $isEdit = $response !== null;
    $values = $old['values'] ?? ($response ? getResponseValues($pdo, (int)$response['id']) : []);
    $title = $old['title'] ?? ($response['title'] ?? '');
    $client = $old['client_name'] ?? ($response['client_name'] ?? '');
    $site = $old['site_location'] ?? ($response['site_location'] ?? '');
    $formTitle = $isEdit ? 'Editar resposta' : 'Nova resposta';

    ob_start(); ?>
    <div class="bg-white p-4 rounded shadow-sm">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4 mb-0"><?=h($formTitle)?></h1>
        <a class="btn btn-outline-secondary" href="?action=list_responses">Voltar</a>
      </div>
      <?php if($errors): ?>
        <div class="alert alert-danger">
          <ul class="mb-0">
            <?php foreach($errors as $error): ?><li><?=h($error)?></li><?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>
      <form method="post" action="?action=save_response">
        <?php if($isEdit): ?><input type="hidden" name="id" value="<?=$response['id']?>"><?php endif; ?>
        <div class="mb-3">
          <label class="form-label">Título <span class="text-danger">*</span></label>
          <input class="form-control" name="title" value="<?=h($title)?>" required>
        </div>
        <div class="row g-3">
          <div class="col-md-6">
            <label class="form-label">Cliente</label>
            <input class="form-control" name="client_name" value="<?=h($client)?>">
          </div>
          <div class="col-md-6">
            <label class="form-label">Site / Local</label>
            <input class="form-control" name="site_location" value="<?=h($site)?>">
          </div>
        </div>
        <?php foreach($structure as $section): ?>
          <div class="mt-4">
            <h2 class="h5"><?=h($section['name'])?></h2>
            <div class="row g-3">
              <?php foreach($section['questions'] as $question): ?>
                <div class="col-12">
                  <?php $field = $question['key_name']; $value = $values[$field] ?? ''; $required = (int)$question['required'] === 1; ?>
                  <label class="form-label"><?=h($question['label'])?><?=$required ? ' <span class="text-danger">*</span>' : ''?></label>
                  <?php
                    $type = $question['type'];
                    $inputName = "q[".$field."]";
                    $attrs = $required ? ' required' : '';
                    if ($type === 'textarea') {
                        $rows = $question['key_name'] === 'layout_tipo' ? 10 : 3;
                        ?>
                        <div class="input-group">
                          <textarea class="form-control" name="<?=$inputName?>" rows="<?=$rows?>" style="overflow:auto;"<?=$attrs?>><?=h($value)?></textarea>
                          <button type="button" class="btn btn-outline-secondary" onclick="fetchAiSuggestion('<?=h($question['label'])?>', this)">Sugerir IA</button>
                        </div>
                        <?php
                    } elseif ($type === 'select') {
                        $options = array_filter(array_map('trim', preg_split('/[\n,]+/', (string)$question['options'])));
                        ?>
                        <select class="form-select" name="<?=$inputName?>"<?=$attrs?>>
                          <option value="">Selecione...</option>
                          <?php foreach($options as $option): ?>
                            <option value="<?=h($option)?>" <?=$option === $value ? 'selected' : ''?>><?=h($option)?></option>
                          <?php endforeach; ?>
                        </select>
                        <?php
                    } else {
                        $inputType = in_array($type, ['number','date']) ? $type : 'text';
                        ?>
                        <div class="input-group">
                          <input type="<?=$inputType?>" class="form-control" name="<?=$inputName?>" value="<?=h($value)?>"<?=$attrs?><?= $inputType==='number' ? ' step="any"' : '' ?>>
                          <button type="button" class="btn btn-outline-secondary" onclick="fetchAiSuggestion('<?=h($question['label'])?>', this)">Sugerir IA</button>
                        </div>
                        <?php
                    }
                  ?>
                </div>
              <?php endforeach; ?>
            </div>
          </div>
        <?php endforeach; ?>
        <div class="d-flex justify-content-end mt-4">
          <button class="btn btn-primary">Salvar</button>
        </div>
      </form>
    </div>
    <?php layout(ob_get_clean(), ($formTitle . ' – ' . APP_TITLE));
}

function handle_save_response(PDO $pdo): void {
    requireAnyAccess();
    $id = isset($_POST['id']) ? (int)$_POST['id'] : null;
    $existing = $id ? ensureResponseAccess($pdo, $id) : null;
    $structure = fetchSurveyStructure($pdo);

    $title = trim((string)($_POST['title'] ?? ''));
    $client = trim((string)($_POST['client_name'] ?? ''));
    $site = trim((string)($_POST['site_location'] ?? ''));
    $valuesInput = $_POST['q'] ?? [];
    if (!is_array($valuesInput)) $valuesInput = [];

    $errors = [];
    if ($title === '') {
        $errors[] = 'O campo título é obrigatório.';
    }

    foreach ($structure as $section) {
        foreach ($section['questions'] as $question) {
            if ((int)$question['required'] === 1) {
                $field = $question['key_name'];
                $value = $valuesInput[$field] ?? '';
                if (is_array($value)) $value = implode(',', $value);
                if (trim((string)$value) === '') {
                    $errors[] = 'A pergunta "' . $question['label'] . '" é obrigatória.';
                }
            }
        }
    }

    if ($errors) {
        $old = [
            'title' => $title,
            'client_name' => $client,
            'site_location' => $site,
            'values' => array_map(static fn($v) => is_array($v) ? implode(',', $v) : (string)$v, $valuesInput)
        ];
        page_response_form($pdo, $existing, $old, $errors);
        return;
    }

    $submitterEmail = actorSubmitterEmail($existing);
    $now = nowIso();

    $pdo->beginTransaction();
    try {
        if ($existing) {
            $stmt = $pdo->prepare("UPDATE responses SET title=?, client_name=?, site_location=?, submitter_email=?, updated_at=? WHERE id=?");
            $stmt->execute([
                $title,
                $client !== '' ? $client : null,
                $site !== '' ? $site : null,
                $submitterEmail,
                $now,
                $existing['id']
            ]);
            $pdo->prepare("DELETE FROM response_values WHERE response_id=?")->execute([$existing['id']]);
            $responseId = (int)$existing['id'];
        } else {
            $stmt = $pdo->prepare("INSERT INTO responses (title, client_name, site_location, submitter_email, created_at, updated_at) VALUES (?,?,?,?,?,?)");
            $stmt->execute([
                $title,
                $client !== '' ? $client : null,
                $site !== '' ? $site : null,
                $submitterEmail,
                $now,
                $now
            ]);
            $responseId = (int)$pdo->lastInsertId();
        }

        $stmtValue = $pdo->prepare("INSERT INTO response_values (response_id, question_id, value) VALUES (?,?,?)");
        foreach ($structure as $section) {
            foreach ($section['questions'] as $question) {
                $field = $question['key_name'];
                $value = $valuesInput[$field] ?? '';
                if (is_array($value)) $value = implode(',', $value);
                $stmtValue->execute([$responseId, $question['id'], $value]);
            }
        }

        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    setFlash($existing ? 'Resposta atualizada com sucesso.' : 'Resposta criada com sucesso.');
    redirect('?action=view_response&id=' . $responseId);
}

function page_view_response(PDO $pdo, int $id): void {
    requireAnyAccess();
    $response = ensureResponseAccess($pdo, $id);
    $values = getResponseValues($pdo, $id);
    $structure = fetchSurveyStructure($pdo);
    $attachments = getAttachments($pdo, $id);
    $flash = popFlash();

    ob_start(); ?>
    <div class="d-flex justify-content-between align-items-center mb-3">
      <div>
        <h1 class="h4 mb-1">Resposta #<?=$response['id']?></h1>
        <div class="text-muted small">Atualizado em <?=$response['updated_at']?> | Criado em <?=$response['created_at']?></div>
      </div>
      <div class="d-flex gap-2">
        <a class="btn btn-outline-secondary" href="?action=list_responses">Voltar</a>
        <a class="btn btn-primary" href="?action=edit_response&amp;id=<?=$response['id']?>">Editar</a>
      </div>
    </div>
    <?php if($flash): ?><div class="alert alert-success"><?=h($flash)?></div><?php endif; ?>
    <div class="bg-white p-4 rounded shadow-sm mb-4">
      <dl class="row mb-0">
        <dt class="col-sm-3">Título</dt><dd class="col-sm-9"><?=h($response['title'])?></dd>
        <dt class="col-sm-3">Cliente</dt><dd class="col-sm-9"><?=h($response['client_name'])?></dd>
        <dt class="col-sm-3">Site</dt><dd class="col-sm-9"><?=h($response['site_location'])?></dd>
        <dt class="col-sm-3">Contato</dt><dd class="col-sm-9"><?=h($response['submitter_email'])?></dd>
      </dl>
    </div>
    <?php foreach($structure as $section): ?>
      <div class="bg-white p-4 rounded shadow-sm mb-4">
        <h2 class="h5 mb-3"><?=h($section['name'])?></h2>
        <dl class="row mb-0">
          <?php foreach($section['questions'] as $question):
              $field=$question['key_name'];
              $rawValue=(string)($values[$field] ?? '');
              $display=trim($rawValue) === '' ? '<span class="text-muted">Sem resposta</span>' : nl2br(h($rawValue));
          ?>
            <dt class="col-sm-4 col-lg-3"><?=h($question['label'])?></dt>
            <dd class="col-sm-8 col-lg-9"><?=$display?></dd>
          <?php endforeach; ?>
        </dl>
      </div>
    <?php endforeach; ?>

    <div class="bg-white p-4 rounded shadow-sm">
      <h2 class="h5 mb-3">Anexos</h2>
      <?php if(empty($attachments)): ?>
        <p class="text-muted">Nenhum anexo enviado.</p>
      <?php else: ?>
        <ul class="list-group mb-3">
          <?php foreach($attachments as $att): ?>
            <li class="list-group-item d-flex justify-content-between align-items-center">
              <div>
                <a href="uploads/<?=h($att['filename'])?>" target="_blank"><?=h($att['original_name'])?></a>
                <div class="small text-muted">Enviado em <?=$att['uploaded_at']?></div>
              </div>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php endif; ?>
      <?php if(currentUser()): ?>
      <form method="post" action="?action=upload_attachment" enctype="multipart/form-data" class="d-flex gap-2">
        <input type="hidden" name="response_id" value="<?=$response['id']?>">
        <input type="file" name="file" class="form-control" required>
        <button class="btn btn-outline-primary">Enviar</button>
      </form>
      <?php else: ?>
        <p class="small text-muted mb-0">Somente usuários autenticados podem enviar anexos.</p>
      <?php endif; ?>
    </div>
    <?php layout(ob_get_clean(), 'Resposta #' . $response['id'] . ' – ' . APP_TITLE);
}

// ---------- Upload ----------
if ($action==='upload_attachment' && $_SERVER['REQUEST_METHOD']==='POST') {
    requireSurveyAccess();
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
    requireSurveyAccess();
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
        <thead><tr><th>ID</th><th>Título</th><th>Cliente</th><th>Local</th><th>E-mail</th><th>Criado</th></tr></thead>
        <tbody>
        <?php foreach($rows as $r): ?>
          <tr>
            <td><?=$r['id']?></td>
            <td><?=h($r['title'])?></td>
            <td><?=h($r['client_name'])?></td>
            <td><?=h($r['site_location'])?></td>
            <td><?=h($r['submitter_email'])?></td>
            <td><?=$r['created_at']?></td>
          </tr>
        <?php endforeach;?>
        </tbody>
      </table>
    </div>
    <?php layout(ob_get_clean(),"Relatórios – ".APP_TITLE);
}

function page_users(PDO $pdo): void {
    requireLogin();
    $flash = popFlash();
    $users = $pdo->query("SELECT id, username, api_token FROM users ORDER BY username")
        ->fetchAll(PDO::FETCH_ASSOC);
    $current = currentUser();

    ob_start(); ?>
    <div class="d-flex align-items-center justify-content-between mb-3">
      <h1 class="h4 mb-0">Usuários</h1>
      <a class="btn btn-primary" href="?action=new_user">Novo usuário</a>
    </div>
    <?php if($flash): ?>
      <div class="alert alert-success"><?=h($flash)?></div>
    <?php endif; ?>
    <div class="bg-white p-3 rounded shadow-sm">
      <table class="table table-striped align-middle">
        <thead><tr><th>Usuário</th><th>Token da API</th><th class="text-end">Ações</th></tr></thead>
        <tbody>
        <?php foreach($users as $user): ?>
          <tr>
            <td><?=h($user['username'])?></td>
            <td><code><?=h($user['api_token'])?></code></td>
            <td class="text-end">
              <a class="btn btn-sm btn-outline-secondary" href="?action=edit_user&amp;id=<?=$user['id']?>">Editar</a>
              <form method="post" action="?action=regen_user_token" class="d-inline">
                <input type="hidden" name="id" value="<?=$user['id']?>">
                <button class="btn btn-sm btn-outline-secondary" onclick="return confirm('Gerar um novo token para este usuário?');">Novo token</button>
              </form>
              <?php if($current && (int)$current['id'] === (int)$user['id']): ?>
                <button class="btn btn-sm btn-outline-danger" disabled title="Não é possível excluir o próprio usuário">Excluir</button>
              <?php else: ?>
                <form method="post" action="?action=delete_user" class="d-inline" onsubmit="return confirm('Excluir usuário <?=h($user['username'])?>?');">
                  <input type="hidden" name="id" value="<?=$user['id']?>">
                  <button class="btn btn-sm btn-outline-danger">Excluir</button>
                </form>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php layout(ob_get_clean(), "Usuários – ".APP_TITLE); }

function page_user_form(PDO $pdo, ?array $user = null, string $error = '', array $old = []): void {
    requireLogin();
    $isEdit = $user !== null;
    $title = $isEdit ? 'Editar usuário' : 'Novo usuário';
    $username = $old['username'] ?? ($user['username'] ?? '');

    ob_start(); ?>
    <div class="bg-white p-4 rounded shadow-sm" style="max-width:500px;margin:auto;">
      <h1 class="h4 mb-3"><?=h($title)?></h1>
      <?php if($error): ?><div class="alert alert-danger"><?=h($error)?></div><?php endif; ?>
      <form method="post" action="?action=<?=$isEdit ? 'edit_user&amp;id='.$user['id'] : 'new_user'?>">
        <div class="mb-3">
          <label class="form-label">Usuário</label>
          <input class="form-control" name="username" value="<?=h($username)?>" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Senha <?=$isEdit ? '<small class="text-muted">(deixe em branco para manter)</small>' : ''?></label>
          <input type="password" class="form-control" name="password" <?=$isEdit ? '' : 'required'?>>
        </div>
        <?php if($isEdit): ?>
          <div class="mb-3">
            <label class="form-label">Token atual da API</label>
            <div class="input-group">
              <input class="form-control" value="<?=h($user['api_token'])?>" readonly>
              <button class="btn btn-outline-secondary" name="regen_token" value="1">Gerar novo token</button>
            </div>
            <small class="text-muted">Salvará alterações e atribuirá um novo token imediatamente.</small>
          </div>
        <?php endif; ?>
        <div class="d-flex justify-content-between">
          <a class="btn btn-link" href="?action=users">Cancelar</a>
          <button class="btn btn-primary">Salvar</button>
        </div>
      </form>
    </div>
    <?php layout(ob_get_clean(), $title." – ".APP_TITLE); }

// ---------- Layout ----------
function layout(string $content,string $title=APP_TITLE):void{
    $u=currentUser();
    $guest=guestEmail();
    echo "<!doctype html><html><head><meta charset='utf-8'><title>".h($title)."</title>
    <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'></head><body>
    <nav class='navbar navbar-dark bg-dark navbar-expand'><div class='container'>
      <a class='navbar-brand' href='?'>".APP_TITLE."</a>

      <div class='navbar-nav'>
        <a class='nav-link' href='?action=list_responses'>Respostas</a>
        <a class='nav-link' href='?action=reports'>Relatórios</a>";
    if($u){ echo "<a class='nav-link' href='?action=users'>Usuários</a>"; echo "<a class='nav-link' href='?action=logout'>Logout (".h($u['username']).")</a>"; }
    elseif(($guest = guestEmail())) { echo "<span class='nav-link disabled text-white-50'>Convidado: ".h($guest)."</span>"; echo "<a class='nav-link' href='?action=guest_logout'>Sair</a>"; }
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
          credentials: 'same-origin',
          body: JSON.stringify({ prompt, context })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          const message = data.error || `Erro HTTP ${res.status}`;
          throw new Error(message);
        }
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

function page_guest_access(string $error = '', string $email = ''): void { ob_start(); ?>
  <div class="bg-white p-4 rounded shadow-sm" style="max-width:420px;margin:auto;">
    <h1 class="h4 mb-3">Acesso como convidado</h1>
    <p class="text-muted">Informe seu e-mail para acessar o questionário como convidado.</p>
    <form method="post" action="?action=guest_access" novalidate>
      <div class="mb-3">
        <label class="form-label" for="guest-email">E-mail</label>
        <input
          type="email"
          id="guest-email"
          name="email"
          class="form-control<?=$error ? ' is-invalid' : ''?>"
          value="<?=h($email)?>"
          required
        >
        <?php if($error): ?><div class="invalid-feedback d-block"><?=h($error)?></div><?php endif; ?>
      </div>
      <div class="d-flex justify-content-between align-items-center">
        <a class="btn btn-link" href="?">Cancelar</a>
        <button class="btn btn-primary">Continuar</button>
      </div>
    </form>
  </div>
<?php layout(ob_get_clean(),"Acesso de convidado – ".APP_TITLE); }

// ---------- Dispatch ----------
if($action==='save_response' && $_SERVER['REQUEST_METHOD']==='POST'){
    handle_save_response($pdo);
}
elseif($action==='new_response'){
    page_response_form($pdo);
}
elseif($action==='edit_response'){
    requireAnyAccess();
    $id=(int)($_GET['id'] ?? 0);
    $response=ensureResponseAccess($pdo, $id);
    $old=[
        'title'=>$response['title'] ?? '',
        'client_name'=>$response['client_name'] ?? '',
        'site_location'=>$response['site_location'] ?? '',
        'values'=>getResponseValues($pdo, $response['id'])
    ];
    page_response_form($pdo,$response,$old);
}
elseif($action==='view_response'){
    $id=(int)($_GET['id'] ?? 0);
    page_view_response($pdo,$id);
}
elseif($action==='delete_response' && $_SERVER['REQUEST_METHOD']==='POST'){
    requireLogin();
    $id=(int)$_POST['id'];
    $exists=getResponse($pdo,$id);
    if($exists){
        $pdo->prepare("DELETE FROM responses WHERE id=?")->execute([$id]);
        setFlash('Resposta excluída.');
    } else {
        setFlash('Resposta não encontrada.');
    }
    redirect('?action=list_responses');
}
elseif($action==='list_responses'){
    page_list_responses($pdo);
}
elseif($action==='login' && $_SERVER['REQUEST_METHOD']==='POST'){
    $u=$_POST['username']; $p=$_POST['password'];
    $st=$pdo->prepare("SELECT * FROM users WHERE username=?");$st->execute([$u]);$usr=$st->fetch();
    if($usr && password_verify($p,$usr['password_hash'])){$_SESSION['uid']=$usr['id'];redirect("?");}
    else{ page_login("Usuário/senha inválidos"); }
}
elseif($action==='login'){ page_login(); }
elseif($action==='logout'){ session_destroy(); redirect("?"); }
elseif($action==='guest_access'){
    if($_SERVER['REQUEST_METHOD']==='POST'){
        $email=trim($_POST['email']??'');
        if($email===''){
            page_guest_access('Informe um e-mail.', $email);
        } elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            page_guest_access('E-mail inválido. Verifique e tente novamente.', $email);
        } else {
            grantGuestAccess($email);
            redirect('?action=list_responses');
        }
    } else {
        page_guest_access('', guestEmail() ?? '');
    }
}
elseif($action==='guest_logout'){
    revokeGuestAccess();
    redirect('?');
}
elseif($action==='users'){ page_users($pdo); }
elseif($action==='new_user'){
    requireLogin();
    if($_SERVER['REQUEST_METHOD']==='POST'){
        $username=trim($_POST['username']??'');
        $password=$_POST['password']??'';
        if($username==='' || $password===''){
            page_user_form($pdo,null,'Usuário e senha são obrigatórios.', ['username'=>$username]);
        } else {
            $hash=password_hash($password,PASSWORD_BCRYPT);
            $token=bin2hex(random_bytes(16));
            try{
                $pdo->prepare("INSERT INTO users (username,password_hash,api_token) VALUES (?,?,?)")
                    ->execute([$username,$hash,$token]);
            }catch(PDOException $e){
                if($e->getCode()==='23000'){
                    page_user_form($pdo,null,'Nome de usuário já está em uso.', ['username'=>$username]);
                } else {
                    throw $e;
                }
                return;
            }
            setFlash('Usuário criado com sucesso.');
            redirect('?action=users');
        }
    } else {
        page_user_form($pdo);
    }
}
elseif($action==='edit_user'){
    requireLogin();
    $id=(int)($_GET['id'] ?? $_POST['id'] ?? 0);
    $st=$pdo->prepare("SELECT * FROM users WHERE id=?");
    $st->execute([$id]);
    $user=$st->fetch(PDO::FETCH_ASSOC);
    if(!$user){
        setFlash('Usuário não encontrado.');
        redirect('?action=users');
    }
    if($_SERVER['REQUEST_METHOD']==='POST'){
        $username=trim($_POST['username']??'');
        $password=$_POST['password']??'';
        $regen=isset($_POST['regen_token']);
        if($username===''){
            page_user_form($pdo,$user,'O campo usuário é obrigatório.', ['username'=>$username]);
            return;
        }
        $params=[$username];
        $sql="UPDATE users SET username=?";
        if($password!==''){
            $sql.=', password_hash=?';
            $params[]=password_hash($password,PASSWORD_BCRYPT);
        }
        if($regen){
            $sql.=', api_token=?';
            $params[]=bin2hex(random_bytes(16));
        }
        $sql.=' WHERE id=?';
        $params[]=$id;
        try{
            $pdo->prepare($sql)->execute($params);
        }catch(PDOException $e){
            if($e->getCode()==='23000'){
                page_user_form($pdo,$user,'Nome de usuário já está em uso.', ['username'=>$username]);
            } else {
                throw $e;
            }
            return;
        }
        setFlash('Usuário atualizado com sucesso.');
        redirect('?action=users');
    } else {
        page_user_form($pdo,$user);
    }
}
elseif($action==='delete_user' && $_SERVER['REQUEST_METHOD']==='POST'){
    requireLogin();
    $id=(int)$_POST['id'];
    $current=currentUser();
    if($current && (int)$current['id']===$id){
        setFlash('Não é possível excluir o próprio usuário.');
    } else {
        $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$id]);
        setFlash('Usuário excluído.');
    }
    redirect('?action=users');
}
elseif($action==='regen_user_token' && $_SERVER['REQUEST_METHOD']==='POST'){
    requireLogin();
    $id=(int)$_POST['id'];
    $token=bin2hex(random_bytes(16));
    $pdo->prepare("UPDATE users SET api_token=? WHERE id=?")->execute([$token,$id]);
    setFlash('Novo token gerado com sucesso.');
    redirect('?action=users');
}
elseif($action==='reports'){ page_reports($pdo); }
else { page_home(); }
