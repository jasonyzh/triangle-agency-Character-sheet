/* 生成 PWA 图标（纯 Node，无依赖）：白底红三角（any）+ 红底白三角（maskable 安全区）
   用法：node scripts/make-pwa-icons.js */
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'public', 'icons');
const BRAND = [0xd8, 0x40, 0x2f];      // #d8402f
const BRAND_DARK = [0xb5, 0x30, 0x1f]; // 描边深红

/* ---- 最小 PNG 编码器 ---- */
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}
function encodePNG(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6;   // 8bit RGBA
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;   // filter: none
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0))
  ]);
}

/* ---- 三角形图标绘制 ---- */
/* inside(x,y): p0→p1→p2 逆/顺时针同侧测试 */
function inTriangle(x, y, p) {
  const s = (a, b) => (x - a[0]) * (b[1] - a[1]) - (b[0] - a[0]) * (y - a[1]);
  const d1 = s(p[0], p[1]), d2 = s(p[1], p[2]), d3 = s(p[2], p[0]);
  const neg = d1 < 0 || d2 < 0 || d3 < 0, pos = d1 > 0 || d2 > 0 || d3 > 0;
  return !(neg && pos);
}
function draw(size, mode) {
  const rgba = Buffer.alloc(size * size * 4);
  // 三角顶点：any = 大三角（白底红三角）；maskable = 红底白三角，内容缩在 80% 安全区内
  const big = mode === 'any';
  const bg = big ? [0xff, 0xff, 0xff] : BRAND;
  const fg = big ? BRAND : [0xff, 0xff, 0xff];
  const pad = big ? size * 0.10 : size * 0.34;   // maskable 四周留 34% 安全边
  const tri = [
    [size / 2, pad],
    [size - pad, size - pad * 0.9],
    [pad, size - pad * 0.9]
  ];
  const edge = size * (big ? 0.015 : 0.012);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4;
      rgba[i] = bg[0]; rgba[i + 1] = bg[1]; rgba[i + 2] = bg[2]; rgba[i + 3] = 255;
      if (inTriangle(x + 0.5, y + 0.5, tri)) {
        rgba[i] = fg[0]; rgba[i + 1] = fg[1]; rgba[i + 2] = fg[2];
      }
      // any 模式：三角外圈加深色描边（近似 favicon 的 stroke）
      if (big) {
        const grow = [[tri[0][0], tri[0][1] - edge], [tri[1][0] + edge, tri[1][1] + edge], [tri[2][0] - edge, tri[2][1] + edge]];
        if (!inTriangle(x + 0.5, y + 0.5, tri) && inTriangle(x + 0.5, y + 0.5, grow)) {
          rgba[i] = BRAND_DARK[0]; rgba[i + 1] = BRAND_DARK[1]; rgba[i + 2] = BRAND_DARK[2];
        }
      }
    }
  }
  return encodePNG(size, rgba);
}

fs.mkdirSync(OUT, { recursive: true });
[[192, 'any'], [512, 'any'], [192, 'maskable'], [512, 'maskable']].forEach(function (cfg) {
  const file = path.join(OUT, 'icon-' + cfg[0] + (cfg[1] === 'maskable' ? '-maskable' : '') + '.png');
  fs.writeFileSync(file, draw(cfg[0], cfg[1]));
  console.log('生成', path.relative(process.cwd(), file), fs.statSync(file).size + 'B');
});
