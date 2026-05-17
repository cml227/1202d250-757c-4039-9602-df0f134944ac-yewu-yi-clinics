/**
 * @file ZerocostBuilder Runtime Loader (Browser / Service Worker / Node ≥ 18)
 * ============================================================================
 * 逻辑演进足迹
 * ----------------------------------------------------------------------------
 * 2026-05-14  v4 唯一标准（彻底清理 v1/v2/v3 残留）
 *   - 移除 keyResolver / masterKey / 旧 ABI（zcb_init 4 参数版 + zcb_decrypt_wasm）
 *   - 仅保留 schemaVersion=3「四元锚定」加载路径
 *   - JS 端无任何途径派生真 masterKey / 真 dataKey
 * 2026-05-14  bizId 强制非空契约（与构建侧 buildAndPublish 入口校验对齐）
 *   - 加载阶段校验 boot.json.bizId 必须为非空字符串，否则立即抛错
 *   - buildInfo 删除空 bizId 兜底分支；zcb_init 调用始终带非空 bizId 参数
 *   - 简化导出：runtime.bizId 直接返回 boot.json 中的值（永远非空）
 * 2026-05-15  多 Origin 故障转移内置（§5.1 韧性运行时落实）
 *   - 新增 ZcbRuntime.loadWithFailover(origins, options)：按顺序尝试 origins
 *     列表，第一个成功即返回；全失败时抛错并把 err.attempts 含每个 Origin 的
 *     失败原因数组。可通过 onFailover 回调钩入业务方打点 / 日志
 *   - 替代之前需要业务方自己写 for-loop 的散落实现（README §2.5.2 示例）
 * 2026-05-15  defaultFetcher CORS preflight bug 修复（§5.7 跨域 header 陷阱）
 *   - 删除 noCache 时添加的 Cache-Control / Pragma 自定义 header
 *   - 这些 header 会触发 CORS preflight，而绝大多数 CDN（jsDelivr/unpkg/CFP/
 *     gitlab-raw/npm tarball）不在 Access-Control-Allow-Headers 列出
 *     Cache-Control → preflight 失败 → 浏览器抛 "Failed to fetch"
 *   - fetch 自身的 cache: 'no-store' 已足以实现 no-cache 语义
 *
 * 三环境共享的引导加载器。零三方依赖，仅使用平台标准 API：
 *   - WebCrypto (`crypto.subtle`)
 *   - WebAssembly
 *   - fetch（可被自定义 `fetcher` 覆盖以适配 file:// / 内存源 / 自建协议）
 *   - TextEncoder / TextDecoder / URL
 *
 * ## 端到端流程（schemaVersion=3，C 终端用户完全无感）
 *   1. `fetcher('boot.json', baseUrl)` → 取得引导索引 + anchors[3] 索引。
 *   2. 并行 fetch 3 个外部锚点完整 64B buffer（无 keyResolver、无 masterKey 输入）。
 *   3. 伪 bootstrapKey ← HKDF(SHA-256(concat(buf2,buf3,buf4)))（与构建侧 KDF 字节一致）。
 *   4. 用伪 bootstrapKey 解 `core.wasm.enc` → `WebAssembly.instantiate(wasmBytes, {})`。
 *      WASM 内嵌 12B Anchor1Seed + 6B ANCHOR_MODES（构建期注入，攻击者必须逆向 wasm
 *      才能拿到）。
 *   5. 把 3 个完整 64B buffer + bizId 喂进 `zcb_init`（8 参数 ABI）。
 *      WASM 内部按 ANCHOR_MODES 从 buffer 抽取 12B × 3 + ANCHOR1_SEED → 48B 真 masterKey
 *      → HKDF → 真 dataKey（JS 永远拿不到）。
 *   6. 解密 manifest（经 WASM 内真 dataKey）→ 建立 `originalPath → encryptedName` 索引。
 *   7. `runtime.getFile(originalPath)`：按需 fetch + WASM 解密。
 *
 *   关键安全属性（与 lib.rs 的 ADR-001 对齐）：
 *     - 业务方 B 嵌入 loader 即可，无需提供任何密钥；C 终端用户完全无感
 *     - 攻击者只逆向 loader.mjs → 只能拿到 3 个完整 anchor buffer
 *       （但不知哪些 12B 是密钥）
 *     - 攻击者必须额外逆向 wasm 二进制找 ANCHOR1_SEED + ANCHOR_MODES 才能完成密钥重组
 *
 * ## 业务隔离（v4 唯一标准 · bizId 强制非空）
 *   boot.json.bizId 必须为非空字符串。loader 会在加载阶段拒绝缺失/空白的 bizId。
 *   HKDF info 拼接为 `<base_info>:<bizId>`，使同一真 masterKey 在不同业务下派生
 *   密码学独立的子密钥。
 *
 * ## 失效模式（与上游 §5.7 对齐）
 *   - boot.json schemaVersion ≠ 3                → 抛 "schemaVersion 不支持"
 *   - boot.json.bizId 缺失或为空                   → 抛 "boot.json.bizId 必须为非空"
 *   - anchors 数量或长度异常                       → 抛错（明确指明）
 *   - 任一 anchor fetch 失败                      → 抛 fetch 错（fetcher 自带）
 *   - 伪 bootstrapKey 解 wasm 鉴权失败             → AEAD 抛错（密钥配错的标志）
 *   - zcb_init 返回非零                           → 抛 WASM 错误码
 *   - 内容寻址 SHA-256 不符                       → 抛错（CDN 替换或中间人攻击的前置拦截）
 * ============================================================================
 */

// ---- 平台抽象 ----

/** 取 WebCrypto subtle（浏览器/SW 直接拿；Node 18 在 webcrypto，Node 19+ 全局可用）。 */
async function getSubtle() {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  const nodeCrypto = await import('node:crypto');
  return nodeCrypto.webcrypto.subtle;
}

/**
 * 默认 fetcher：使用 fetch 拉取 `new URL(filename, baseUrl)`，返回 Uint8Array。
 *
 * 缓存策略（关键 · §5.7 失效预测：preflight 与跨域 CORS）：
 *   - **boot.json**（mutable，每次部署变内容但 URL 固定）→ `cache:'no-store'`
 *     仅依赖 fetch 内置 cache 选项绕开浏览器/SW 缓存；
 *     CDN 边缘缓存由 ZCB 在 deploy 时通过 jsDelivr Purge API 主动清除。
 *   - **<SHA256>.enc**（immutable，内容寻址）→ `cache:'force-cache'`，
 *     文件名与内容 1:1 绑定，永远可放心强缓存（节省带宽 + 加速）。
 *
 * 严禁添加 `Cache-Control` / `Pragma` 等自定义 header：
 *   跨域 CDN（jsDelivr / unpkg / GitLab raw / CFP / NPM tarball 等）通常**不**把
 *   Cache-Control 列入 `Access-Control-Allow-Headers`，加自定义请求头会触发
 *   CORS preflight (OPTIONS) → 大多数 CDN 不响应或返回 405 → `Failed to fetch`。
 *   fetch 自身的 cache: 'no-store' 已足以实现 no-cache 语义，无需任何 header。
 *
 * 调用方若需要细粒度控制，可传 options.noCache=true/false 覆盖此默认值，
 * 或通过 options.fetcher 完全自定义（如同源场景下加 header 而无 CORS 问题）。
 */
async function defaultFetcher(filename, baseUrl, options = {}) {
  if (typeof fetch !== 'function') {
    throw new Error('当前环境无 fetch，请传入自定义 fetcher（如 fs-based）');
  }
  const isBootIndex = filename === 'boot.json';
  const noCache = options?.noCache ?? isBootIndex;

  const url = new URL(filename, baseUrl);
  const resp = await fetch(url, {
    cache: noCache ? 'no-store' : 'force-cache',
    redirect: 'follow'
  });
  if (!resp.ok) throw new Error(`fetch 失败 ${resp.status}: ${url.toString()}`);
  const ab = await resp.arrayBuffer();
  return new Uint8Array(ab);
}

const ENC = new TextEncoder();
const DEC = new TextDecoder();

// ---- 加密原语：HKDF-SHA256 + AES-256-GCM（与 Rust crate 端常量字节级一致） ----

const HKDF_SALT = ENC.encode('ZerocostBuilder/v1');
const INFO_BOOTSTRAP_KEY = ENC.encode('wasm-bootstrap-key');

/**
 * 构造 HKDF info：base + ':' + bizId。
 *
 * v4 唯一标准下 bizId 强制非空（boot.json 责名期已校验），此处直接拼接。
 * 必须与 wasm-src/zcb-decryptor/src/lib.rs::build_info() 及
 * src/buildAndPublish.mjs::buildInfo() 字节级一致。
 */
function buildInfo(base, bizId) {
  const idBytes = ENC.encode(bizId);
  const out = new Uint8Array(base.length + 1 + idBytes.length);
  out.set(base, 0);
  out[base.length] = 0x3a; // ':'
  out.set(idBytes, base.length + 1);
  return out;
}

async function hkdfDerive(subtle, masterKeyBytes, info, lenBits = 256) {
  const base = await subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info },
    base,
    lenBits
  );
  return new Uint8Array(bits);
}

/**
 * 计算 SHA-256 并返回 64 位 hex。用于内容寻址交叉验签：
 *   sha(密文 bundle) 必须等于 文件名（去掉 .enc 后缀）。
 * 双重防护：① AEAD GCM AuthTag 保证密文未被篡改 ② 文件名 hash 保证 CDN 路径未被替换。
 */
async function sha256Hex(subtle, bytes) {
  const hash = await subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(hash)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** 若文件名是 `<64-hex>.enc` 形式，对 bundle 做内容寻址校验；其他形式（如 boot.json）跳过。 */
async function verifyContentAddressed(subtle, filename, bundle) {
  const m = /^([0-9a-f]{64})\.enc$/i.exec(filename);
  if (!m) return; // 非内容寻址命名（如 boot.json）→ 不校验
  const expected = m[1].toLowerCase();
  const actual = await sha256Hex(subtle, bundle);
  if (expected !== actual) {
    throw new Error(
      `内容寻址校验失败 ${filename}: 期望 sha=${expected}, 实际 sha=${actual}`
    );
  }
}

/**
 * 解密 `[12B IV][16B Tag][Ciphertext]` 布局的 AEAD bundle。
 * WebCrypto 期望 ciphertext 后接 tag → 此处重排。
 */
async function decryptAesGcm(subtle, bundle, keyBytes) {
  if (bundle.length < 28) throw new Error('bundle 过短（< 28B）');
  const iv = bundle.subarray(0, 12);
  const tag = bundle.subarray(12, 28);
  const ct = bundle.subarray(28);
  const ctWithTag = new Uint8Array(ct.length + tag.length);
  ctWithTag.set(ct, 0);
  ctWithTag.set(tag, ct.length);
  const key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  try {
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ctWithTag);
    return new Uint8Array(plain);
  } catch (e) {
    // SubtleCrypto.decrypt 鉴权失败时抛出 DOMException(name="OperationError")，
    // 但 Chromium 系 message 为空字符串 —— 转译为带可操作根因的明确错误，
    // 满足规则 5.7「失效模式可被感知」与 6.1「禁止静默吞错」。
    const why =
      'AES-GCM 鉴权失败：' +
      '密文/AuthTag 与所提供密钥不匹配。\n' +
      '可能根因（按概率排序）：\n' +
      '  1. 锚点 buffer 与构建侧不一致（CDN 缓存延迟或 anchors 索引被替换）\n' +
      '  2. bizId 与加密时不一致（HKDF info 字节不同 → 派生子密钥不同）\n' +
      '  3. 资产在传输中被 CDN/代理/中间人替换（启用了内容寻址哈希时此项应已被前置拦截）';
    const orig = e && (e.name || e.constructor?.name) ? `（原始异常：${e.name || e.constructor.name}）` : '';
    throw new Error(why + orig);
  }
}

// ---- WASM 状态码常量（必须与 wasm-src/zcb-decryptor/src/lib.rs 同步） ----
// 仅保留 3 个状态：UNINIT / ACTIVE / DESTROYED

export const STATUS = Object.freeze({
  UNINIT: 0,
  ACTIVE: 1,
  DESTROYED: 4
});

// ---- 导出名映射（与 src/internal/wasm-tools.mjs::DEFAULT_RENAME_MAP 字节一致） ----
// 当 boot.json.wasmObfuscated === true 时使用此短名映射；否则用原 zcb_* 名。
const ORIG_EXPORT_NAMES = Object.freeze({
  zcb_alloc:        'zcb_alloc',
  zcb_free:         'zcb_free',
  zcb_init:         'zcb_init',
  zcb_decrypt_data: 'zcb_decrypt_data',
  zcb_destroy:      'zcb_destroy',
  zcb_status:       'zcb_status'
});
const OBFUSCATED_EXPORT_NAMES = Object.freeze({
  zcb_alloc:        'a',
  zcb_free:         'b',
  zcb_init:         'c',
  zcb_decrypt_data: 'd',
  zcb_destroy:      'e',
  zcb_status:       'f'
});

const ERR_NAMES = Object.freeze({
  '-1': 'UNINITIALIZED',
  '-2': 'ALREADY_INITIALIZED',
  '-3': 'DESTROYED',
  '-7': 'BUNDLE_TOO_SHORT',
  '-8': 'AEAD_DECRYPT_FAIL',
  '-9': 'OUT_CAPACITY_TOO_SMALL',
  '-10': 'HKDF_FAIL',
  '-11': 'NULL_POINTER',
  '-13': 'ANCHOR_BAD_LEN',
  '-14': 'BIZ_ID_REQUIRED'
});

function errnoMessage(errno) {
  const name = ERR_NAMES[String(errno)] || 'UNKNOWN';
  return `WASM errno=${errno} (${name})`;
}

// ---- WASM 调用桥 ----

/**
 * 取 WASM 导出函数（应用导出名映射）。
 * 如 wasm 经过混淆后处理，则 `zcb_alloc` 实际可能叫 `a`，loader 通过映射屏蔽这个差异。
 */
function exp(instance, exportMap, name) {
  const realName = exportMap[name] || name;
  const fn = instance.exports[realName];
  if (typeof fn !== 'function') {
    throw new Error(`WASM 缺失导出 ${name}（实际查找名=${realName}）`);
  }
  return fn;
}

/** 把 Uint8Array 写入 WASM 线性内存并返回 (ptr, len)。 */
function writeBytesToWasm(instance, exportMap, bytes) {
  const ptr = exp(instance, exportMap, 'zcb_alloc')(bytes.length);
  if (ptr === 0) throw new Error('zcb_alloc 返回空指针');
  new Uint8Array(instance.exports.memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

/** 调用 zcb_decrypt_data 解密 bundle。 */
function callDecrypt(instance, exportMap, bundle) {
  const fn = exp(instance, exportMap, 'zcb_decrypt_data');
  const free = exp(instance, exportMap, 'zcb_free');
  const inHandle = writeBytesToWasm(instance, exportMap, bundle);
  const outCap = Math.max(bundle.length - 28, 16);
  const outPtr = exp(instance, exportMap, 'zcb_alloc')(outCap);
  try {
    const written = fn(inHandle.ptr, inHandle.len, outPtr, outCap);
    if (written < 0) throw new Error(errnoMessage(written));
    return new Uint8Array(
      new Uint8Array(instance.exports.memory.buffer, outPtr, written)
    );
  } finally {
    free(inHandle.ptr, inHandle.len);
    free(outPtr, outCap);
  }
}

// ---- 加载路径常量 ----

/** 期望的外部锚点数量（与 buildAndPublish 中 EXTERNAL_ANCHOR_COUNT 一致） */
const EXTERNAL_ANCHOR_COUNT = 3;
/** 每个外部锚点 buffer 的固定长度（与 lib.rs 中 EXTERNAL_BUF_LEN 一致） */
const EXTERNAL_BUF_LEN = 64;
/** 当前唯一支持的 schemaVersion */
const SUPPORTED_SCHEMA_VERSION = 3;

// ---- ZcbRuntime（主入口） ----

export class ZcbRuntime {
  /**
   * 加载并初始化运行时。返回可立即 getFile 的 Runtime 实例。
   *
   * @param {string | URL} bootUrl - 资源根 URL，runtime 将以此为 base 拉取 boot.json
   *   及各 .enc 文件。Node 环境可用 `file://` URL。
   * @param {Object} [options]
   * @param {(filename: string, baseUrl: string | URL) => Promise<Uint8Array>} [options.fetcher]
   *   自定义资源读取器，默认使用 fetch。
   * @returns {Promise<ZcbRuntime>}
   */
  static async load(bootUrl, options = {}) {
    const { fetcher = defaultFetcher } = options;

    const subtle = await getSubtle();

    // Step 1：boot.json (强制 no-cache，避免拿到旧版本指引)
    const bootBytes = await fetcher('boot.json', bootUrl, { noCache: true });
    const bootJson = JSON.parse(DEC.decode(bootBytes));
    if (bootJson.schemaVersion !== SUPPORTED_SCHEMA_VERSION) {
      throw new Error(
        `boot.json schemaVersion 不支持：${bootJson.schemaVersion}（仅支持 ${SUPPORTED_SCHEMA_VERSION}「四元锚定」）`
      );
    }
    if (!Array.isArray(bootJson.anchors) || bootJson.anchors.length !== EXTERNAL_ANCHOR_COUNT) {
      throw new Error(
        `schemaVersion=${SUPPORTED_SCHEMA_VERSION} 要求 boot.json.anchors 为 ${EXTERNAL_ANCHOR_COUNT} 元素数组，实际：${bootJson.anchors?.length}`
      );
    }
    if (typeof bootJson.bizId !== 'string' || !bootJson.bizId.trim()) {
      throw new Error(
        'boot.json.bizId 必须为非空字符串（v4「四元锚定」唯一标准）；' +
        '空 bizId 会破坏多业务密钥域隔离，远端资产形态不合规。'
      );
    }
    const bizId = bootJson.bizId.trim();

    // Step 2：并行拉取 3 个外部锚点 buffer（完整 64B）
    const anchorBuffers = await Promise.all(
      bootJson.anchors.map((a) => fetcher(a.filename, bootUrl))
    );
    for (let i = 0; i < anchorBuffers.length; i++) {
      if (anchorBuffers[i].length !== EXTERNAL_BUF_LEN) {
        throw new Error(
          `anchor ${bootJson.anchors[i].index} 长度异常: ${anchorBuffers[i].length} 应为 ${EXTERNAL_BUF_LEN}`
        );
      }
    }

    // Step 3：伪 bootstrapKey 输入 = SHA-256(buf2 || buf3 || buf4)
    //   这样 JS 端在不知 modes 的情况下也能复现与构建侧一致的 KDF input
    const concatBuf = new Uint8Array(EXTERNAL_BUF_LEN * EXTERNAL_ANCHOR_COUNT);
    for (let i = 0; i < anchorBuffers.length; i++) {
      concatBuf.set(anchorBuffers[i], i * EXTERNAL_BUF_LEN);
    }
    const anchorsSha = new Uint8Array(await subtle.digest('SHA-256', concatBuf));
    const fakeBootKey = await hkdfDerive(subtle, anchorsSha, buildInfo(INFO_BOOTSTRAP_KEY, bizId));

    // Step 4：解密 wasm.enc → 实例化
    const wasmEnc = await fetcher(bootJson.wasm.filename, bootUrl);
    await verifyContentAddressed(subtle, bootJson.wasm.filename, wasmEnc);
    let wasmBytes;
    try {
      wasmBytes = await decryptAesGcm(subtle, wasmEnc, fakeBootKey);
    } finally {
      fakeBootKey.fill(0);
    }
    if (wasmBytes.length < 8 || wasmBytes[0] !== 0x00 || wasmBytes[1] !== 0x61 || wasmBytes[2] !== 0x73 || wasmBytes[3] !== 0x6d) {
      throw new Error('WASM 解密后魔数校验失败（伪 bootstrapKey 与构建侧不一致）');
    }

    const { instance } = await WebAssembly.instantiate(wasmBytes, {});
    const exportMap = bootJson.wasmObfuscated === true ? OBFUSCATED_EXPORT_NAMES : ORIG_EXPORT_NAMES;

    // Step 5：把 3 个完整 64B buffer + bizId 喂给 zcb_init（8 参数 ABI）
    // v4 唯一标准下 bizId 强制非空，无需空字符串兜底。
    const h2 = writeBytesToWasm(instance, exportMap, anchorBuffers[0]);
    const h3 = writeBytesToWasm(instance, exportMap, anchorBuffers[1]);
    const h4 = writeBytesToWasm(instance, exportMap, anchorBuffers[2]);
    const bidBytes = ENC.encode(bizId);
    const bidH = writeBytesToWasm(instance, exportMap, bidBytes);

    const initResult = exp(instance, exportMap, 'zcb_init')(
      h2.ptr, h2.len,
      h3.ptr, h3.len,
      h4.ptr, h4.len,
      bidH.ptr, bidH.len
    );
    exp(instance, exportMap, 'zcb_free')(h2.ptr, h2.len);
    exp(instance, exportMap, 'zcb_free')(h3.ptr, h3.len);
    exp(instance, exportMap, 'zcb_free')(h4.ptr, h4.len);
    exp(instance, exportMap, 'zcb_free')(bidH.ptr, bidH.len);
    if (initResult !== 0) {
      throw new Error(`zcb_init 失败：${errnoMessage(initResult)}`);
    }

    // Step 6：解密 manifest（同样做内容寻址校验）
    const manifestEnc = await fetcher(bootJson.manifest.filename, bootUrl);
    await verifyContentAddressed(subtle, bootJson.manifest.filename, manifestEnc);
    const manifestBytes = callDecrypt(instance, exportMap, manifestEnc);
    const manifest = JSON.parse(DEC.decode(manifestBytes));

    return new ZcbRuntime(instance, bootJson, bootUrl, manifest, fetcher, exportMap, subtle);
  }

  /**
   * 多 Origin 故障转移加载（§5.1 韧性策略的运行时落实）。
   *
   * 按顺序尝试 origins 列表中的每个 baseUrl，第一个成功即返回该 runtime。
   * 单 Origin 失败的常见原因：CDN edge cache 滞后（如 GitHub raw 5min）/ 网络
   * 出口限制（如 GFW 拦 github.com）/ 远端尚未同步完成（如 CFP 异步部署中）。
   *
   * @param {Array<string | URL>} origins - baseUrl 数组（按优先级排序）
   * @param {Object} [options]
   * @param {(filename: string, baseUrl: string | URL) => Promise<Uint8Array>} [options.fetcher]
   * @param {(attempt: {origin: string|URL, error: Error}) => void} [options.onFailover]
   *   每次单 Origin 失败的回调（用于业务方打点 / 日志记录）。
   * @returns {Promise<ZcbRuntime>}
   * @throws {Error} 所有 Origin 均失败时，err.attempts 含每个 Origin 的失败原因数组。
   *
   * @example
   * const runtime = await ZcbRuntime.loadWithFailover([
   *   'https://b28c869d-...-v4.pages.dev/',
   *   'https://cdn.jsdelivr.net/gh/cml227/b28c869d-...-v4@main/',
   *   'https://cdn.jsdelivr.net/npm/@cml227/zcb-encrypted-assets-v4@latest/dist/'
   * ], {
   *   onFailover: ({ origin, error }) => console.warn(`[zcb] origin 失败: ${origin}`, error.message)
   * });
   */
  static async loadWithFailover(origins, options = {}) {
    if (!Array.isArray(origins) || origins.length === 0) {
      throw new Error('loadWithFailover 至少需要 1 个 origin');
    }
    const { onFailover, ...loadOpts } = options;
    const attempts = [];
    for (const origin of origins) {
      try {
        return await ZcbRuntime.load(origin, loadOpts);
      } catch (err) {
        const record = { origin: String(origin), error: err };
        attempts.push(record);
        if (typeof onFailover === 'function') {
          try { onFailover(record); } catch { /* 用户回调失败不阻塞 */ }
        }
      }
    }
    const aggErr = new Error(
      `所有 ${origins.length} 个 Origin 均加载失败：\n` +
        attempts.map((a, i) => `  [${i + 1}] ${a.origin}\n      ${String(a.error.message || a.error).slice(0, 200)}`).join('\n')
    );
    aggErr.attempts = attempts;
    throw aggErr;
  }

  constructor(instance, bootJson, bootUrl, manifest, fetcher, exportMap, subtle) {
    this._instance = instance;
    this._boot = bootJson;
    this._baseUrl = bootUrl;
    this._manifest = manifest;
    this._fetcher = fetcher;
    this._exportMap = exportMap || ORIG_EXPORT_NAMES;
    this._subtle = subtle;
    this._pathIndex = new Map(manifest.files.map((f) => [f.originalPath, f]));
  }

  /** 当前 boot.json 中声明的密钥代际（仅审计标识，不参与密码学派生）。 */
  /** 当前 runtime 成功加载的 baseUrl（loadWithFailover 后用于诊断"实际命中哪个 Origin"）。 */
  get baseUrl() { return this._baseUrl; }

  get keyVersion() { return this._boot.keyVersion || 'v1'; }
  /** 当前业务 ID（v4 唯一标准下由 boot.json 携带且强制非空，业务级密钥隔离恒启用）。 */
  get bizId()      { return this._boot.bizId; }
  /** 当前清单 schema 版本（恒为 3）。 */
  get schemaVersion() { return this._boot.schemaVersion; }
  /** 构建时间戳（UTC ISO 字符串）。 */
  get builtAt()    { return this._boot.builtAt; }
  /** 所有可访问的资产原始路径。 */
  get paths()      { return [...this._pathIndex.keys()]; }

  /**
   * 按原始路径拉取并解密资产。
   * @param {string} originalPath
   * @returns {Promise<Uint8Array>}
   */
  async getFile(originalPath) {
    const entry = this._pathIndex.get(originalPath);
    if (!entry) throw new Error(`未知资产路径：${originalPath}`);
    const bundle = await this._fetcher(entry.encryptedName, this._baseUrl);
    // 内容寻址交叉验签（防 CDN/代理换包；与 AEAD AuthTag 形成双重防护）
    if (this._subtle) {
      await verifyContentAddressed(this._subtle, entry.encryptedName, bundle);
    }
    const plain = callDecrypt(this._instance, this._exportMap, bundle);
    if (plain.length !== entry.plaintextLen) {
      throw new Error(
        `明文长度不匹配 path=${originalPath} expected=${entry.plaintextLen} got=${plain.length}`
      );
    }
    return plain;
  }

  /** 显式销毁运行时（清零 WASM 内部密钥）。幂等。 */
  destroy() {
    try { exp(this._instance, this._exportMap, 'zcb_destroy')(); } catch { /* WASM 已 trap，忽略 */ }
  }

  /** 查询 WASM 状态码（取自 STATUS 常量）。 */
  status() {
    return exp(this._instance, this._exportMap, 'zcb_status')();
  }
}

export default ZcbRuntime;
