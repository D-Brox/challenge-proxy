// Image rotation estimator: recovers the clockwise angle by which a
// centered square crop was rotated. Works on raw RGBA byte arrays.
export function estimateRotationAngle(originalRGBA, originalWidth, rotatedRGBA, rotatedWidth) {
  const size = rotatedWidth;
  const total = size * size;
  const offset = (originalWidth - size) / 2;

  const refGray = new Float32Array(total);
  const rotGray = new Float32Array(total);
  const rotAlpha = new Float32Array(total);

  for (let i = 0; i < total; i++) {
    const rOff = ((Math.floor(i / size) + offset) * originalWidth + (i % size) + offset) * 4;
    const r = originalRGBA[rOff];
    const g = originalRGBA[rOff + 1];
    const b = originalRGBA[rOff + 2];
    refGray[i] = (r + g + b) / 3;
    const tOff = i * 4;
    const tr = rotatedRGBA[tOff];
    const tg = rotatedRGBA[tOff + 1];
    const tb = rotatedRGBA[tOff + 2];
    rotGray[i] = (tr + tg + tb) / 3;
    rotAlpha[i] = rotatedRGBA[tOff + 3];
  }

  const ALPHA_THRESHOLD = 128;
  const COARSE_GRID = 128;
  const MIN_VALID_PIXELS = 100;
  const center = (size - 1) / 2;

  const scale = size / COARSE_GRID;
  const gridPoints = COARSE_GRID * COARSE_GRID;
  const gridX = new Float32Array(gridPoints);
  const gridY = new Float32Array(gridPoints);
  const refSamples = new Float32Array(gridPoints);
  for (let i = 0; i < gridPoints; i++) {
    const gx = (i % COARSE_GRID) * scale;
    const gy = Math.floor(i / COARSE_GRID) * scale;
    gridX[i] = gx;
    gridY[i] = gy;
    refSamples[i] = refGray[Math.floor(gy) * size + Math.floor(gx)];
  }

  let bestAngle = 0;
  let bestScore = Number.MAX_VALUE;
  for (let a = 0; a < 360; a++) {
    const rad = (a * Math.PI) / 180.0;
    const ca = Math.cos(rad);
    const sa = Math.sin(rad);
    let sum = 0;
    let valid = 0;
    for (let i = 0; i < gridPoints; i++) {
      const vx = gridX[i] - center;
      const vy = gridY[i] - center;
      const qx = center + vx * ca + vy * sa;
      const qy = center - vx * sa + vy * ca;
      if (qx < 0 || qx >= size || qy < 0 || qy >= size) continue;
      const idx = Math.floor(qy) * size + Math.floor(qx);
      if (rotAlpha[idx] <= ALPHA_THRESHOLD) continue;
      const d = refSamples[i] - rotGray[idx];
      sum += d * d;
      valid++;
    }
    if (valid < MIN_VALID_PIXELS) continue;
    const score = sum / valid;
    if (score < bestScore) {
      bestScore = score;
      bestAngle = a;
    }
  }

  return bestAngle;
}
