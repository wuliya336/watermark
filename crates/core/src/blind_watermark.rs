use nalgebra::{SMatrix, SVD};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use rayon::prelude::*;
use std::sync::OnceLock;

// ============================================================
// 常量
// ============================================================
const BLOCK_SIZE: usize = 4;
const D1: f32 = 8.0;
const D2: f32 = 4.0;

// ============================================================
// 预计算 DCT cos 表 (线程安全懒加载)
// ============================================================
static DCT_COS_TABLE: OnceLock<[[f32; 4]; 4]> = OnceLock::new();

fn get_dct_cos_table() -> &'static [[f32; 4]; 4] {
    DCT_COS_TABLE.get_or_init(|| {
        let mut table = [[0.0f32; 4]; 4];
        for u in 0..4 {
            for x in 0..4 {
                table[u][x] =
                    ((2 * x + 1) as f32 * u as f32 * std::f32::consts::PI / 8.0).cos();
            }
        }
        table
    })
}

// ============================================================
// 颜色空间转换
// ============================================================
fn rgb_to_yuv(r: f32, g: f32, b: f32) -> (f32, f32, f32) {
    let y = 0.299 * r + 0.587 * g + 0.114 * b;
    let u = -0.169 * r - 0.331 * g + 0.500 * b + 128.0;
    let v = 0.500 * r - 0.419 * g - 0.081 * b + 128.0;
    (y, u, v)
}

fn yuv_to_rgb(y: f32, u: f32, v: f32) -> (f32, f32, f32) {
    let r = y + 1.402 * (v - 128.0);
    let g = y - 0.344136 * (u - 128.0) - 0.714136 * (v - 128.0);
    let b = y + 1.772 * (u - 128.0);
    (r.clamp(0.0, 255.0), g.clamp(0.0, 255.0), b.clamp(0.0, 255.0))
}

// ============================================================
// Haar DWT2
// ============================================================
fn haar_dwt2(data: &[f32], width: usize, height: usize) -> (Vec<f32>, Vec<f32>, Vec<f32>, Vec<f32>) {
    let half_w = (width + 1) / 2;
    let half_h = (height + 1) / 2;

    let mut ca = vec![0.0f32; half_h * half_w];
    let mut ch = vec![0.0f32; half_h * half_w];
    let mut cv = vec![0.0f32; half_h * half_w];
    let mut cd = vec![0.0f32; half_h * half_w];

    for y in 0..half_h {
        for x in 0..half_w {
            let y0 = y * 2;
            let y1 = (y * 2 + 1).min(height - 1);
            let x0 = x * 2;
            let x1 = (x * 2 + 1).min(width - 1);

            let a = data[y0 * width + x0];
            let b = data[y0 * width + x1];
            let c = data[y1 * width + x0];
            let d = data[y1 * width + x1];

            let idx = y * half_w + x;
            ca[idx] = (a + b + c + d) * 0.5;
            ch[idx] = (a + b - c - d) * 0.5;
            cv[idx] = (a - b + c - d) * 0.5;
            cd[idx] = (a - b - c + d) * 0.5;
        }
    }

    (ca, ch, cv, cd)
}

fn haar_idwt2(
    ca: &[f32],
    ch: &[f32],
    cv: &[f32],
    cd: &[f32],
    width: usize,
    height: usize,
) -> Vec<f32> {
    let half_w = (width + 1) / 2;
    let half_h = (height + 1) / 2;

    let mut data = vec![0.0f32; width * height];

    for y in 0..half_h {
        for x in 0..half_w {
            let idx = y * half_w + x;
            let c_a = ca[idx];
            let c_h = ch[idx];
            let c_v = cv[idx];
            let c_d = cd[idx];

            let y0 = y * 2;
            let y1 = (y * 2 + 1).min(height - 1);
            let x0 = x * 2;
            let x1 = (x * 2 + 1).min(width - 1);

            data[y0 * width + x0] = (c_a + c_h + c_v + c_d) * 0.5;
            data[y0 * width + x1] = (c_a + c_h - c_v - c_d) * 0.5;
            data[y1 * width + x0] = (c_a - c_h + c_v - c_d) * 0.5;
            data[y1 * width + x1] = (c_a - c_h - c_v + c_d) * 0.5;
        }
    }

    data
}

// ============================================================
// 4x4 DCT-II / IDCT
// ============================================================
fn dct2_4x4(block: &[[f32; 4]; 4]) -> [[f32; 4]; 4] {
    let cos_table = get_dct_cos_table();
    let mut out = [[0.0f32; 4]; 4];

    for u in 0..4 {
        for v in 0..4 {
            let alpha_u = if u == 0 { 0.5 } else { std::f32::consts::SQRT_2 * 0.5 };
            let alpha_v = if v == 0 { 0.5 } else { std::f32::consts::SQRT_2 * 0.5 };

            let mut sum = 0.0f32;
            for x in 0..4 {
                for y in 0..4 {
                    sum += block[x][y] * cos_table[u][x] * cos_table[v][y];
                }
            }
            out[u][v] = alpha_u * alpha_v * sum;
        }
    }

    out
}

fn idct2_4x4(block: &[[f32; 4]; 4]) -> [[f32; 4]; 4] {
    let cos_table = get_dct_cos_table();
    let mut out = [[0.0f32; 4]; 4];

    for x in 0..4 {
        for y in 0..4 {
            let mut sum = 0.0f32;
            for u in 0..4 {
                for v in 0..4 {
                    let alpha_u = if u == 0 { 0.5 } else { std::f32::consts::SQRT_2 * 0.5 };
                    let alpha_v = if v == 0 { 0.5 } else { std::f32::consts::SQRT_2 * 0.5 };
                    sum += alpha_u * alpha_v * block[u][v] * cos_table[u][x] * cos_table[v][y];
                }
            }
            out[x][y] = sum;
        }
    }

    out
}

// ============================================================
// SVD (4x4)
// ============================================================
fn svd_4x4(block: &[[f32; 4]; 4]) -> Option<([[f32; 4]; 4], [f32; 4], [[f32; 4]; 4])> {
    let mat = SMatrix::<f32, 4, 4>::from_row_slice(&[
        block[0][0], block[0][1], block[0][2], block[0][3],
        block[1][0], block[1][1], block[1][2], block[1][3],
        block[2][0], block[2][1], block[2][2], block[2][3],
        block[3][0], block[3][1], block[3][2], block[3][3],
    ]);

    let svd = SVD::new(mat, true, true);
    let u = svd.u?;
    let s = svd.singular_values;
    let v_t = svd.v_t?;

    let mut u_arr = [[0.0f32; 4]; 4];
    let mut s_arr = [0.0f32; 4];
    let mut vh_arr = [[0.0f32; 4]; 4];

    for i in 0..4 {
        for j in 0..4 {
            u_arr[i][j] = u[(i, j)];
            vh_arr[i][j] = v_t[(i, j)];
        }
        s_arr[i] = s[i];
    }

    Some((u_arr, s_arr, vh_arr))
}

fn svd_reconstruct(u: &[[f32; 4]; 4], s: &[f32], vh: &[[f32; 4]; 4]) -> [[f32; 4]; 4] {
    let mut out = [[0.0f32; 4]; 4];

    let mut temp = [[0.0f32; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            temp[i][j] = u[i][j] * s[j];
        }
    }

    for i in 0..4 {
        for j in 0..4 {
            let mut sum = 0.0f32;
            for k in 0..4 {
                sum += temp[i][k] * vh[k][j];
            }
            out[i][j] = sum;
        }
    }

    out
}

// ============================================================
// 随机策略
// ============================================================
fn random_strategy1(seed: u64, size: usize, block_shape: usize) -> Vec<Vec<usize>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut result = Vec::with_capacity(size);

    for _ in 0..size {
        let mut values: Vec<(f64, usize)> = (0..block_shape)
            .map(|i| (rng.r#gen::<f64>(), i))
            .collect();
        values.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        result.push(values.iter().map(|(_, i)| *i).collect());
    }

    result
}

// ============================================================
// 水印比特处理
// ============================================================
fn text_to_bits(text: &str) -> Vec<bool> {
    let bytes = text.as_bytes();
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for i in (0..8).rev() {
            bits.push(((byte >> i) & 1) == 1);
        }
    }
    bits
}

fn bits_to_text(bits: &[bool]) -> Option<String> {
    if bits.is_empty() {
        return None;
    }
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - i);
            }
        }
        bytes.push(byte);
    }
    String::from_utf8(bytes).ok()
}

fn shuffle_wm_bits(bits: &mut [bool], seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let len = bits.len();
    for i in (1..len).rev() {
        let j = rng.gen_range(0..=i);
        bits.swap(i, j);
    }
}

fn extract_decrypt(wm_avg: &mut [f32], seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let len = wm_avg.len();
    let mut wm_index: Vec<usize> = (0..len).collect();

    for i in (1..len).rev() {
        let j = rng.gen_range(0..=i);
        wm_index.swap(i, j);
    }

    let mut result = vec![0.0f32; len];
    for i in 0..len {
        result[wm_index[i]] = wm_avg[i];
    }
    wm_avg.copy_from_slice(&result);
}

// ============================================================
// 量化嵌入 / 提取
// ============================================================
fn quantize_embed(s: f32, d: f32, wm_bit: bool) -> f32 {
    let base = (s / d).floor();
    let offset = if wm_bit { 0.75 } else { 0.25 };
    (base + offset) * d
}

fn quantize_extract(s: f32, d: f32) -> f32 {
    if (s % d) > (d / 2.0) { 1.0 } else { 0.0 }
}

// ============================================================
// K-means
// ============================================================
fn one_dim_kmeans(inputs: &[f32]) -> Vec<bool> {
    if inputs.is_empty() {
        return Vec::new();
    }

    let min_val = inputs.iter().cloned().fold(f32::INFINITY, f32::min);
    let max_val = inputs.iter().cloned().fold(f32::NEG_INFINITY, f32::max);

    if (max_val - min_val).abs() < 1e-8 {
        return vec![false; inputs.len()];
    }

    let mut center_low = min_val;
    let mut center_high = max_val;
    let mut threshold = (center_low + center_high) / 2.0;
    let e_tol = 1e-6;

    for _ in 0..300 {
        let mut sum_low = 0.0f32;
        let mut count_low = 0usize;
        let mut sum_high = 0.0f32;
        let mut count_high = 0usize;

        for &v in inputs {
            if v <= threshold {
                sum_low += v;
                count_low += 1;
            } else {
                sum_high += v;
                count_high += 1;
            }
        }

        let new_center_low = if count_low > 0 { sum_low / count_low as f32 } else { center_low };
        let new_center_high = if count_high > 0 { sum_high / count_high as f32 } else { center_high };

        let new_threshold = (new_center_low + new_center_high) / 2.0;

        if (new_threshold - threshold).abs() < e_tol {
            threshold = new_threshold;
            break;
        }

        center_low = new_center_low;
        center_high = new_center_high;
        threshold = new_threshold;
    }

    inputs.iter().map(|&v| v > threshold).collect()
}

// ============================================================
// 块级嵌入 / 提取
// ============================================================
fn embed_block(
    block: &[[f32; 4]; 4],
    wm_bit: bool,
    shuffler: &[usize],
    d1: f32,
    d2: f32,
) -> [[f32; 4]; 4] {
    let block_dct = dct2_4x4(block);

    let mut flattened = [0.0f32; 16];
    for i in 0..4 {
        for j in 0..4 {
            flattened[i * 4 + j] = block_dct[i][j];
        }
    }
    let mut shuffled = [0.0f32; 16];
    for i in 0..16 {
        shuffled[i] = flattened[shuffler[i]];
    }
    let mut shuffled_block = [[0.0f32; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            shuffled_block[i][j] = shuffled[i * 4 + j];
        }
    }

    let Some((u, mut s, vh)) = svd_4x4(&shuffled_block) else {
        return *block;
    };

    s[0] = quantize_embed(s[0], d1, wm_bit);
    if d2 > 0.0 {
        s[1] = quantize_embed(s[1], d2, wm_bit);
    }

    let reconstructed = svd_reconstruct(&u, &s, &vh);

    let mut reconstructed_flat = [0.0f32; 16];
    for i in 0..4 {
        for j in 0..4 {
            reconstructed_flat[i * 4 + j] = reconstructed[i][j];
        }
    }
    let mut unshuffled_flat = [0.0f32; 16];
    for i in 0..16 {
        unshuffled_flat[shuffler[i]] = reconstructed_flat[i];
    }
    let mut unshuffled_block = [[0.0f32; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            unshuffled_block[i][j] = unshuffled_flat[i * 4 + j];
        }
    }

    idct2_4x4(&unshuffled_block)
}

fn extract_block(block: &[[f32; 4]; 4], shuffler: &[usize], d1: f32, d2: f32) -> f32 {
    let block_dct = dct2_4x4(block);

    let mut flattened = [0.0f32; 16];
    for i in 0..4 {
        for j in 0..4 {
            flattened[i * 4 + j] = block_dct[i][j];
        }
    }
    let mut shuffled = [0.0f32; 16];
    for i in 0..16 {
        shuffled[i] = flattened[shuffler[i]];
    }
    let mut shuffled_block = [[0.0f32; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            shuffled_block[i][j] = shuffled[i * 4 + j];
        }
    }

    let Some((_, s, _)) = svd_4x4(&shuffled_block) else {
        return 0.0;
    };

    let mut wm = quantize_extract(s[0], d1);
    if d2 > 0.0 {
        let tmp = quantize_extract(s[1], d2);
        wm = (wm * 3.0 + tmp * 1.0) / 4.0;
    }

    wm
}

// ============================================================
// 主函数: 嵌入
// ============================================================
pub fn blind_embed(
    rgba_bytes: &[u8],
    width: usize,
    height: usize,
    watermark_text: &str,
    password_img: u64,
    password_wm: u64,
) -> Option<(Vec<u8>, usize)> {
    if width < 8 || height < 8 || watermark_text.is_empty() {
        return None;
    }

    let pixel_count = width * height;

    // RGB 提取
    let mut rgb_img = vec![0.0f32; pixel_count * 3];
    for i in 0..pixel_count {
        let rgba_idx = i * 4;
        let rgb_idx = i * 3;
        rgb_img[rgb_idx] = rgba_bytes[rgba_idx] as f32;
        rgb_img[rgb_idx + 1] = rgba_bytes[rgba_idx + 1] as f32;
        rgb_img[rgb_idx + 2] = rgba_bytes[rgba_idx + 2] as f32;
    }

    // RGB to YUV
    let mut yuv_img = vec![0.0f32; pixel_count * 3];
    for i in 0..pixel_count {
        let (y, u, v) = rgb_to_yuv(rgb_img[i * 3], rgb_img[i * 3 + 1], rgb_img[i * 3 + 2]);
        yuv_img[i * 3] = y;
        yuv_img[i * 3 + 1] = u;
        yuv_img[i * 3 + 2] = v;
    }

    // 补白边使偶数
    let padded_h = height + (height % 2);
    let padded_w = width + (width % 2);
    let padded_pixels = padded_h * padded_w;
    let mut padded_yuv = vec![0.0f32; padded_pixels * 3];
    for y in 0..height {
        for x in 0..width {
            let src_idx = (y * width + x) * 3;
            let dst_idx = (y * padded_w + x) * 3;
            padded_yuv[dst_idx] = yuv_img[src_idx];
            padded_yuv[dst_idx + 1] = yuv_img[src_idx + 1];
            padded_yuv[dst_idx + 2] = yuv_img[src_idx + 2];
        }
    }

    // 水印比特
    let mut wm_bits = text_to_bits(watermark_text);
    let wm_size = wm_bits.len();
    shuffle_wm_bits(&mut wm_bits, password_wm);

    // 分块参数
    let ca_h = (padded_h + 1) / 2;
    let ca_w = (padded_w + 1) / 2;
    let block_h = ca_h / BLOCK_SIZE;
    let block_w = ca_w / BLOCK_SIZE;
    let block_num = block_h * block_w;

    if block_num == 0 || wm_size > block_num {
        return None;
    }

    let idx_shuffle = random_strategy1(password_img, block_num, BLOCK_SIZE * BLOCK_SIZE);

    // 收集所有块任务
    let mut tasks = Vec::with_capacity(block_num);
    for by in 0..block_h {
        for bx in 0..block_w {
            let block_idx = by * block_w + bx;
            tasks.push((by, bx, block_idx, wm_bits[block_idx % wm_size]));
        }
    }

    // 对每个通道并行处理
    let mut embed_yuv = vec![0.0f32; padded_pixels * 3];

    for ch in 0..3 {
        let mut channel = vec![0.0f32; padded_pixels];
        for i in 0..padded_pixels {
            channel[i] = padded_yuv[i * 3 + ch];
        }

        let (mut ca, ch_coeff, cv_coeff, cd_coeff) = haar_dwt2(&channel, padded_w, padded_h);

        // 并行嵌入所有块
        let results: Vec<(usize, usize, [[f32; 4]; 4])> = tasks
            .par_iter()
            .map(|(by, bx, block_idx, wm_bit)| {
                let mut block = [[0.0f32; 4]; 4];
                for i in 0..BLOCK_SIZE {
                    for j in 0..BLOCK_SIZE {
                        let ca_y = by * BLOCK_SIZE + i;
                        let ca_x = bx * BLOCK_SIZE + j;
                        block[i][j] = ca[ca_y * ca_w + ca_x];
                    }
                }
                let embedded = embed_block(&block, *wm_bit, &idx_shuffle[*block_idx], D1, D2);
                (*by, *bx, embedded)
            })
            .collect();

        // 串行写回（无数据竞争）
        for (by, bx, embedded) in results {
            for i in 0..BLOCK_SIZE {
                for j in 0..BLOCK_SIZE {
                    let ca_y = by * BLOCK_SIZE + i;
                    let ca_x = bx * BLOCK_SIZE + j;
                    ca[ca_y * ca_w + ca_x] = embedded[i][j];
                }
            }
        }

        let reconstructed = haar_idwt2(&ca, &ch_coeff, &cv_coeff, &cd_coeff, padded_w, padded_h);
        for i in 0..padded_pixels {
            embed_yuv[i * 3 + ch] = reconstructed[i];
        }
    }

    // YUV to RGB
    let mut embed_rgb = vec![0.0f32; padded_pixels * 3];
    for i in 0..padded_pixels {
        let (r, g, b) = yuv_to_rgb(embed_yuv[i * 3], embed_yuv[i * 3 + 1], embed_yuv[i * 3 + 2]);
        embed_rgb[i * 3] = r;
        embed_rgb[i * 3 + 1] = g;
        embed_rgb[i * 3 + 2] = b;
    }

    // 裁剪回原始尺寸，转回 RGBA
    let mut output = vec![0u8; pixel_count * 4];
    for y in 0..height {
        for x in 0..width {
            let src_idx = (y * padded_w + x) * 3;
            let dst_idx = (y * width + x) * 4;
            output[dst_idx] = embed_rgb[src_idx] as u8;
            output[dst_idx + 1] = embed_rgb[src_idx + 1] as u8;
            output[dst_idx + 2] = embed_rgb[src_idx + 2] as u8;
            output[dst_idx + 3] = rgba_bytes[dst_idx + 3];
        }
    }

    Some((output, wm_size))
}

// ============================================================
// 主函数: 提取
// ============================================================
pub fn blind_extract(
    rgba_bytes: &[u8],
    width: usize,
    height: usize,
    wm_size: usize,
    password_img: u64,
    password_wm: u64,
) -> Option<String> {
    if width < 8 || height < 8 || wm_size == 0 {
        return None;
    }

    let pixel_count = width * height;

    // RGB 提取
    let mut rgb_img = vec![0.0f32; pixel_count * 3];
    for i in 0..pixel_count {
        let rgba_idx = i * 4;
        let rgb_idx = i * 3;
        rgb_img[rgb_idx] = rgba_bytes[rgba_idx] as f32;
        rgb_img[rgb_idx + 1] = rgba_bytes[rgba_idx + 1] as f32;
        rgb_img[rgb_idx + 2] = rgba_bytes[rgba_idx + 2] as f32;
    }

    // RGB to YUV
    let mut yuv_img = vec![0.0f32; pixel_count * 3];
    for i in 0..pixel_count {
        let (y, u, v) = rgb_to_yuv(rgb_img[i * 3], rgb_img[i * 3 + 1], rgb_img[i * 3 + 2]);
        yuv_img[i * 3] = y;
        yuv_img[i * 3 + 1] = u;
        yuv_img[i * 3 + 2] = v;
    }

    // 补白边使偶数
    let padded_h = height + (height % 2);
    let padded_w = width + (width % 2);
    let padded_pixels = padded_h * padded_w;
    let mut padded_yuv = vec![0.0f32; padded_pixels * 3];
    for y in 0..height {
        for x in 0..width {
            let src_idx = (y * width + x) * 3;
            let dst_idx = (y * padded_w + x) * 3;
            padded_yuv[dst_idx] = yuv_img[src_idx];
            padded_yuv[dst_idx + 1] = yuv_img[src_idx + 1];
            padded_yuv[dst_idx + 2] = yuv_img[src_idx + 2];
        }
    }

    // 分块参数
    let ca_h = (padded_h + 1) / 2;
    let ca_w = (padded_w + 1) / 2;
    let block_h = ca_h / BLOCK_SIZE;
    let block_w = ca_w / BLOCK_SIZE;
    let block_num = block_h * block_w;

    if block_num == 0 {
        return None;
    }

    let idx_shuffle = random_strategy1(password_img, block_num, BLOCK_SIZE * BLOCK_SIZE);

    // 提取每个块的 1 bit (3 通道)
    let mut wm_block_bit = vec![vec![0.0f32; block_num]; 3];

    for ch in 0..3 {
        let mut channel = vec![0.0f32; padded_pixels];
        for i in 0..padded_pixels {
            channel[i] = padded_yuv[i * 3 + ch];
        }

        let (ca, _, _, _) = haar_dwt2(&channel, padded_w, padded_h);

        // 并行提取所有块
        let ch_results: Vec<f32> = (0..block_num)
            .into_par_iter()
            .map(|block_idx| {
                let by = block_idx / block_w;
                let bx = block_idx % block_w;

                let mut block = [[0.0f32; 4]; 4];
                for i in 0..BLOCK_SIZE {
                    for j in 0..BLOCK_SIZE {
                        let ca_y = by * BLOCK_SIZE + i;
                        let ca_x = bx * BLOCK_SIZE + j;
                        block[i][j] = ca[ca_y * ca_w + ca_x];
                    }
                }

                extract_block(&block, &idx_shuffle[block_idx], D1, D2)
            })
            .collect();

        for (i, val) in ch_results.iter().enumerate() {
            wm_block_bit[ch][i] = *val;
        }
    }

    // 对循环嵌入 + 3 通道求平均
    let mut wm_avg = vec![0.0f32; wm_size];
    for i in 0..wm_size {
        let mut sum = 0.0f32;
        let mut count = 0usize;
        for ch in 0..3 {
            for j in (i..block_num).step_by(wm_size) {
                sum += wm_block_bit[ch][j];
                count += 1;
            }
        }
        if count > 0 {
            wm_avg[i] = sum / count as f32;
        }
    }

    // K-means 阈值分割
    let wm_class = one_dim_kmeans(&wm_avg);

    // 解密
    let mut wm_avg_for_decrypt: Vec<f32> = wm_class.iter().map(|&b| if b { 1.0 } else { 0.0 }).collect();
    extract_decrypt(&mut wm_avg_for_decrypt, password_wm);

    // 解码
    let wm_bits: Vec<bool> = wm_avg_for_decrypt.iter().map(|&v| v >= 0.5).collect();
    bits_to_text(&wm_bits)
}
