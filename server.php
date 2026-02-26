<?php
/**
 * PHP Text Intelligence Starter - Backend Server
 *
 * Simple REST API server providing text intelligence analysis
 * powered by Deepgram's Text Intelligence service.
 *
 * Key Features:
 * - Contract-compliant API endpoint: POST /api/text-intelligence
 * - Accepts text or URL in JSON body
 * - Supports multiple intelligence features: summarization, topics, sentiment, intents
 * - CORS-enabled for frontend communication
 * - JWT session auth with rate limiting (production only)
 */

require_once __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Yosymfony\Toml\Toml;

// ============================================================================
// CONFIGURATION
// ============================================================================

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

$CONFIG = [
    'port' => $_ENV['PORT'] ?? '8081',
    'host' => $_ENV['HOST'] ?? '0.0.0.0',
];

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

/**
 * Session secret for signing JWTs.
 * Generated at startup if SESSION_SECRET env var is not set.
 */
$SESSION_SECRET = $_ENV['SESSION_SECRET'] ?? bin2hex(random_bytes(32));

/** JWT expiry time in seconds (1 hour) */
define('JWT_EXPIRY', 3600);

/**
 * Create a signed JWT session token.
 *
 * @param string $secret The secret key for signing
 * @return string The encoded JWT token
 */
function createSessionToken(string $secret): string
{
    $now = time();
    $payload = [
        'iat' => $now,
        'exp' => $now + JWT_EXPIRY,
    ];
    return JWT::encode($payload, $secret, 'HS256');
}

/**
 * Validate JWT from the Authorization header.
 * Returns null on success, or an error response array on failure.
 *
 * @param string $secret The secret key for verification
 * @return array|null Error response or null if valid
 */
function validateSession(string $secret): ?array
{
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (empty($authHeader) || !str_starts_with($authHeader, 'Bearer ')) {
        return [
            'status' => 401,
            'body' => [
                'error' => [
                    'type' => 'AuthenticationError',
                    'code' => 'MISSING_TOKEN',
                    'message' => 'Authorization header with Bearer token is required',
                ],
            ],
        ];
    }

    $token = substr($authHeader, 7);
    try {
        JWT::decode($token, new Key($secret, 'HS256'));
        return null;
    } catch (ExpiredException $e) {
        return [
            'status' => 401,
            'body' => [
                'error' => [
                    'type' => 'AuthenticationError',
                    'code' => 'INVALID_TOKEN',
                    'message' => 'Session expired, please refresh the page',
                ],
            ],
        ];
    } catch (\Exception $e) {
        return [
            'status' => 401,
            'body' => [
                'error' => [
                    'type' => 'AuthenticationError',
                    'code' => 'INVALID_TOKEN',
                    'message' => 'Invalid session token',
                ],
            ],
        ];
    }
}

// ============================================================================
// API KEY LOADING
// ============================================================================

/**
 * Load the Deepgram API key from the environment.
 * Exits with a helpful error message if not found.
 *
 * @return string The API key
 */
function loadApiKey(): string
{
    $apiKey = $_ENV['DEEPGRAM_API_KEY'] ?? '';

    if (empty($apiKey)) {
        fwrite(STDERR, "\nERROR: Deepgram API key not found!\n\n");
        fwrite(STDERR, "Please set your API key in .env file:\n");
        fwrite(STDERR, "   DEEPGRAM_API_KEY=your_api_key_here\n\n");
        fwrite(STDERR, "Get your API key at: https://console.deepgram.com\n\n");
        exit(1);
    }

    return $apiKey;
}

$API_KEY = loadApiKey();

// ============================================================================
// CORS CONFIGURATION
// ============================================================================

/**
 * Set standard CORS headers on the response.
 */
function setCORSHeaders(): void
{
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Send a JSON response with the given HTTP status code.
 *
 * @param int $status HTTP status code
 * @param mixed $data Data to encode as JSON
 */
function sendJSON(int $status, mixed $data): void
{
    setCORSHeaders();
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Send a structured error response.
 *
 * @param int $status HTTP status code
 * @param string $type Error type
 * @param string $code Error code
 * @param string $message Error message
 */
function sendError(int $status, string $type, string $code, string $message): void
{
    sendJSON($status, [
        'error' => [
            'type' => $type,
            'code' => $code,
            'message' => $message,
            'details' => new \stdClass(),
        ],
    ]);
}

// ============================================================================
// ROUTER
// ============================================================================

$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$requestMethod = $_SERVER['REQUEST_METHOD'];

// Handle CORS preflight for all routes
if ($requestMethod === 'OPTIONS') {
    setCORSHeaders();
    http_response_code(204);
    exit;
}

// ============================================================================
// SESSION ROUTES - Auth endpoints (unprotected)
// ============================================================================

/**
 * GET /api/session - Issues a signed JWT for session authentication.
 */
if ($requestUri === '/api/session' && $requestMethod === 'GET') {
    $token = createSessionToken($SESSION_SECRET);
    sendJSON(200, ['token' => $token]);
}

// ============================================================================
// METADATA ROUTE
// ============================================================================

/**
 * GET /api/metadata - Returns metadata from deepgram.toml [meta] section.
 */
if ($requestUri === '/api/metadata' && $requestMethod === 'GET') {
    try {
        $tomlPath = __DIR__ . '/deepgram.toml';
        $config = Toml::parseFile($tomlPath);

        if (!isset($config['meta'])) {
            sendJSON(500, [
                'error' => 'INTERNAL_SERVER_ERROR',
                'message' => 'Missing [meta] section in deepgram.toml',
            ]);
        }

        sendJSON(200, $config['meta']);
    } catch (\Exception $e) {
        error_log('Error reading metadata: ' . $e->getMessage());
        sendJSON(500, [
            'error' => 'INTERNAL_SERVER_ERROR',
            'message' => 'Failed to read metadata from deepgram.toml',
        ]);
    }
}

// ============================================================================
// API ROUTES
// ============================================================================

/**
 * POST /api/text-intelligence
 *
 * Contract-compliant text intelligence endpoint per starter-contracts specification.
 * Accepts:
 * - Query parameters: summarize, topics, sentiment, intents, language (all optional)
 * - Body: JSON with either text or url field (required, not both)
 *
 * Returns:
 * - Success (200): JSON with results object containing requested intelligence features
 * - Error (4XX): JSON error response matching contract format
 */
if ($requestUri === '/api/text-intelligence' && $requestMethod === 'POST') {
    // Auth check
    $authError = validateSession($SESSION_SECRET);
    if ($authError !== null) {
        sendJSON($authError['status'], $authError['body']);
    }

    // Parse JSON body
    $rawBody = file_get_contents('php://input');
    $body = json_decode($rawBody, true);

    if ($body === null && !empty($rawBody)) {
        sendError(400, 'validation_error', 'INVALID_TEXT', 'Invalid JSON body');
    }

    $text = $body['text'] ?? null;
    $url = $body['url'] ?? null;

    // Validate: exactly one of text or url
    if (empty($text) && empty($url)) {
        sendError(400, 'validation_error', 'INVALID_TEXT', "Request must contain either 'text' or 'url' field");
    }

    if (!empty($text) && !empty($url)) {
        sendError(400, 'validation_error', 'INVALID_TEXT', "Request must contain either 'text' or 'url', not both");
    }

    // If URL provided, validate and fetch text content
    $textContent = $text;
    if (!empty($url)) {
        // Validate URL format
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            sendError(400, 'validation_error', 'INVALID_URL', 'Invalid URL format');
        }

        // Fetch text from URL
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 30,
        ]);
        $fetchedContent = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($fetchedContent === false) {
            sendError(400, 'validation_error', 'INVALID_URL', 'Failed to fetch URL: ' . $curlError);
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            sendError(400, 'validation_error', 'INVALID_URL', 'Failed to fetch URL: HTTP ' . $httpCode);
        }

        $textContent = $fetchedContent;
    }

    // Check for empty text
    if (empty(trim($textContent ?? ''))) {
        sendError(400, 'validation_error', 'EMPTY_TEXT', 'Text content cannot be empty');
    }

    // Extract query parameters for intelligence features
    $queryParams = [];
    parse_str($_SERVER['QUERY_STRING'] ?? '', $queryParams);

    $language = $queryParams['language'] ?? 'en';
    $summarize = $queryParams['summarize'] ?? null;
    $topics = $queryParams['topics'] ?? null;
    $sentiment = $queryParams['sentiment'] ?? null;
    $intents = $queryParams['intents'] ?? null;

    // Handle summarize v1 rejection
    if ($summarize === 'v1') {
        sendError(400, 'validation_error', 'INVALID_TEXT', 'Summarization v1 is no longer supported. Please use v2 or true.');
    }

    // Build Deepgram API URL with query parameters
    $dgUrl = 'https://api.deepgram.com/v1/read?language=' . urlencode($language);

    if ($summarize === 'true' || $summarize === 'v2') {
        $dgUrl .= '&summarize=v2';
    }
    if ($topics === 'true') {
        $dgUrl .= '&topics=true';
    }
    if ($sentiment === 'true') {
        $dgUrl .= '&sentiment=true';
    }
    if ($intents === 'true') {
        $dgUrl .= '&intents=true';
    }

    // Build request body for Deepgram
    $dgBody = json_encode(['text' => $textContent]);

    // Call Deepgram Read API via cURL
    $ch = curl_init($dgUrl);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $dgBody,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTPHEADER => [
            'Authorization: Token ' . $API_KEY,
            'Content-Type: application/json',
        ],
    ]);

    $dgResponse = curl_exec($ch);
    $dgHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $dgCurlError = curl_error($ch);
    curl_close($ch);

    if ($dgResponse === false) {
        error_log('Deepgram API Error: ' . $dgCurlError);
        sendError(400, 'processing_error', 'INVALID_TEXT', 'Failed to process text: ' . $dgCurlError);
    }

    // Handle non-2xx from Deepgram
    if ($dgHttpCode < 200 || $dgHttpCode >= 300) {
        error_log('Deepgram API Error (status ' . $dgHttpCode . '): ' . $dgResponse);
        sendError(400, 'processing_error', 'INVALID_TEXT', 'Failed to process text');
    }

    // Parse Deepgram response
    $dgResult = json_decode($dgResponse, true);
    if ($dgResult === null) {
        error_log('Deepgram Response Parse Error');
        sendError(500, 'processing_error', 'INVALID_TEXT', 'Failed to parse Deepgram response');
    }

    // Return results (the Deepgram response includes a "results" key)
    $results = $dgResult['results'] ?? new \stdClass();
    sendJSON(200, ['results' => $results]);
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

/**
 * GET /health - Returns a simple health check response.
 */
if ($requestUri === '/health' && $requestMethod === 'GET') {
    sendJSON(200, ['status' => 'ok', 'service' => 'text-intelligence']);
}

// ============================================================================
// 404 NOT FOUND
// ============================================================================

sendJSON(404, ['error' => 'Not Found', 'message' => 'Endpoint not found']);
