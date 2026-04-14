use md5;
use log::debug;
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

const WATERMARK_MAGIC: [u8; 4] = *b"KWM1";
const WATERMARK_V2_MAGIC: [u8; 4] = *b"KWM2";
const MAX_WATERMARK_TEXT_BYTES: usize = 200;
const MAX_WATERMARK_TEXT_BYTES_V1: usize = 48;
const WATERMARK_CHECKSUM_BYTES: usize = 8;
const WATERMARK_PAYLOAD_BYTES: usize = 220;
const WATERMARK_PAYLOAD_BYTES_V1: usize = 64;
const WATERMARK_PAYLOAD_BITS: usize = WATERMARK_PAYLOAD_BYTES * 8;
const WATERMARK_PAYLOAD_BITS_V1: usize = WATERMARK_PAYLOAD_BYTES_V1 * 8;
const WATERMARK_TEXT_LEN_OFFSET: usize = 4;
const WATERMARK_TEXT_OFFSET: usize = 6;

/// 将比特数组转换为字节
fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bits.chunks(8) {
        if chunk.len() < 8 {
            break;
        }
        let mut byte = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            byte |= b << (7 - i);
        }
        out.push(byte);
    }
    out
}

/// 计算字符串的 MD5 校验和（十六进制字符串）
fn compute_checksum(text: &str) -> String {
    format!("{:x}", md5::compute(text.as_bytes()))
}

fn compute_checksum_prefix_bytes(bytes: &[u8]) -> [u8; WATERMARK_CHECKSUM_BYTES] {
    let digest = md5::compute(bytes);
    let mut output = [0u8; WATERMARK_CHECKSUM_BYTES];
    output.copy_from_slice(&digest.0[..WATERMARK_CHECKSUM_BYTES]);
    output
}

fn text_quality_score(text: &str) -> f64 {
    let mut total = 0usize;
    let mut readable = 0usize;
    let mut alnum = 0usize;
    for c in text.chars() {
        total += 1;
        if c.is_alphanumeric() {
            alnum += 1;
            readable += 1;
            continue;
        }
        if c.is_whitespace() || c.is_ascii_punctuation() || (!c.is_control() && !c.is_ascii()) {
            readable += 1;
        }
    }
    if total == 0 {
        return 0.0;
    }
    let readable_ratio = readable as f64 / total as f64;
    let semantic_ratio = alnum as f64 / total as f64;
    readable_ratio * 0.8 + semantic_ratio * 0.2
}

fn build_watermark_payload(watermark_text: &str) -> [u8; WATERMARK_PAYLOAD_BYTES] {
    let mut payload = [0u8; WATERMARK_PAYLOAD_BYTES];
    payload[0..4].copy_from_slice(&WATERMARK_V2_MAGIC);
    let text_bytes = watermark_text.as_bytes();
    let text_len = text_bytes.len().min(MAX_WATERMARK_TEXT_BYTES);
    payload[WATERMARK_TEXT_LEN_OFFSET..WATERMARK_TEXT_OFFSET]
        .copy_from_slice(&(text_len as u16).to_be_bytes());
    payload[WATERMARK_TEXT_OFFSET..WATERMARK_TEXT_OFFSET + text_len]
        .copy_from_slice(&text_bytes[..text_len]);
    let checksum_start = WATERMARK_TEXT_OFFSET + MAX_WATERMARK_TEXT_BYTES;
    let checksum = compute_checksum_prefix_bytes(
        &payload[WATERMARK_TEXT_OFFSET..WATERMARK_TEXT_OFFSET + text_len],
    );
    payload[checksum_start..checksum_start + WATERMARK_CHECKSUM_BYTES].copy_from_slice(&checksum);
    payload
}

fn build_watermark_payload_v1(watermark_text: &str) -> [u8; WATERMARK_PAYLOAD_BYTES_V1] {
    let mut payload = [0u8; WATERMARK_PAYLOAD_BYTES_V1];
    payload[0..4].copy_from_slice(&WATERMARK_MAGIC);
    let text_bytes = watermark_text.as_bytes();
    let text_len = text_bytes.len().min(MAX_WATERMARK_TEXT_BYTES_V1);
    payload[4] = text_len as u8;
    payload[5..5 + text_len].copy_from_slice(&text_bytes[..text_len]);
    let checksum_start = 5 + MAX_WATERMARK_TEXT_BYTES_V1;
    let checksum = compute_checksum_prefix_bytes(&payload[5..5 + text_len]);
    payload[checksum_start..checksum_start + WATERMARK_CHECKSUM_BYTES].copy_from_slice(&checksum);
    payload
}

fn parse_watermark_payload(payload: &[u8]) -> Option<(String, bool)> {
    if payload.len() != WATERMARK_PAYLOAD_BYTES {
        return None;
    }
    if payload[0..4] != WATERMARK_V2_MAGIC {
        // debug!("[DWT Extract] Magic mismatch: {:?}", &payload[0..4]);
        return None;
    }
    let text_len = u16::from_be_bytes(
        payload[WATERMARK_TEXT_LEN_OFFSET..WATERMARK_TEXT_OFFSET]
            .try_into()
            .unwrap_or([0, 0]),
    ) as usize;

    // 无论 text_len 是多少（因为可能被破坏导致截断），我们都强行读取最大的文本区域，
    // 然后去掉多余的 \0，这样即使长度字段损坏，我们也能拿到完整的字符串！
    let full_text_bytes = &payload[WATERMARK_TEXT_OFFSET..WATERMARK_TEXT_OFFSET + MAX_WATERMARK_TEXT_BYTES];
    let text = String::from_utf8_lossy(full_text_bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_string();
    
    if text.is_empty() {
        return None;
    }
    let checksum_start = WATERMARK_TEXT_OFFSET + MAX_WATERMARK_TEXT_BYTES;
    
    // 如果长度没坏，我们尽量去验证它
    let expected = if text_len > 0 && text_len <= MAX_WATERMARK_TEXT_BYTES {
        compute_checksum_prefix_bytes(&payload[WATERMARK_TEXT_OFFSET..WATERMARK_TEXT_OFFSET + text_len])
    } else {
        [0u8; WATERMARK_CHECKSUM_BYTES]
    };
    
    let mut actual = [0u8; WATERMARK_CHECKSUM_BYTES];
    actual.copy_from_slice(&payload[checksum_start..checksum_start + WATERMARK_CHECKSUM_BYTES]);
    Some((text, actual == expected))
}

fn parse_watermark_payload_v1(payload: &[u8]) -> Option<(String, bool)> {
    if payload.len() != WATERMARK_PAYLOAD_BYTES_V1 {
        return None;
    }
    if payload[0..4] != WATERMARK_MAGIC {
        return None;
    }
    let text_len = payload[4] as usize;
    
    let full_text_bytes = &payload[5..5 + MAX_WATERMARK_TEXT_BYTES_V1];
    let text = String::from_utf8_lossy(full_text_bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_string();
    
    if text.is_empty() {
        return None;
    }
    let checksum_start = 5 + MAX_WATERMARK_TEXT_BYTES_V1;
    let expected = if text_len > 0 && text_len <= MAX_WATERMARK_TEXT_BYTES_V1 {
        compute_checksum_prefix_bytes(&payload[5..5 + text_len])
    } else {
        [0u8; WATERMARK_CHECKSUM_BYTES]
    };
    let mut actual = [0u8; WATERMARK_CHECKSUM_BYTES];
    actual.copy_from_slice(&payload[checksum_start..checksum_start + WATERMARK_CHECKSUM_BYTES]);
    Some((text, actual == expected))
}

fn evaluate_payload_candidates(
    bits: &[u8],
    payload_bits: usize,
    payload_bytes: usize,
    parser: fn(&[u8]) -> Option<(String, bool)>,
) -> (Option<String>, f64, Option<String>, f64) {
    let total_bits_len = bits.len();
    let mut best_verified_candidate: Option<String> = None;
    let mut best_verified_score = 0.0f64;
    let mut best_fallback_candidate: Option<String> = None;
    let mut best_fallback_score = 0.0f64;

    debug!("[DWT Extract] evaluate_payload_candidates payload_bytes={}, total_bits_len={}, phase_limit={}", payload_bytes, total_bits_len, payload_bits);

    for phase in 0..payload_bits {
        let remaining = total_bits_len.saturating_sub(phase);
        let copies = remaining / payload_bits;
        
        // 允许只抄写了一遍（或甚至不到一遍的尝试拼接）
        if copies < 1 && remaining < payload_bits / 2 {
            break; // 只有当连半遍都不到时才放弃
        }
        
        let effective_copies = if copies == 0 { 1 } else { copies };

        let mut merged_bits = vec![0u8; payload_bits];
        let mut vote_confidence_sum = 0.0f64;
        for (bit_pos, merged_bit) in merged_bits.iter_mut().enumerate() {
            let mut votes = 0i32;
            let actual_copies = if phase + (effective_copies - 1) * payload_bits + bit_pos < remaining {
                effective_copies
            } else {
                effective_copies.saturating_sub(1)
            };
            
            if actual_copies == 0 {
                // 如果这个位连一次都没抄到，只能蒙一个0
                *merged_bit = 0;
                continue;
            }

            for copy_idx in 0..actual_copies {
                let idx = phase + copy_idx * payload_bits + bit_pos;
                if idx < bits.len() {
                    if bits[idx] == 1 {
                        votes += 1;
                    } else {
                        votes -= 1;
                    }
                }
            }
            *merged_bit = if votes > 0 { 1 } else { 0 };
            vote_confidence_sum += (votes.unsigned_abs() as f64) / (actual_copies as f64);
        }

        let payload = bits_to_bytes(&merged_bits);
        if payload.len() != payload_bytes {
            continue;
        }
        
        // --- ADDED DEBUGGING FOR MAGIC NUMBER ---
        if phase == 0 && payload_bytes == WATERMARK_PAYLOAD_BYTES {
            let magic = &payload[0..4];
            let is_magic_match = magic == WATERMARK_V2_MAGIC;
            let magic_str = String::from_utf8_lossy(magic);
            debug!("[DWT Extract] phase={}, copies={}, remaining={}, magic={:?} (str: '{}'), match={}", phase, copies, remaining, magic, magic_str, is_magic_match);
        }

        if let Some((text, verified)) = parser(&payload) {
            let consistency = vote_confidence_sum / payload_bits as f64;
            let text_quality = text_quality_score(&text);
            let copy_score = (copies as f64 / 12.0).min(1.0);
            let fallback_score = text_quality * 0.3 + consistency * 0.45 + copy_score * 0.25;
            
            debug!("[DWT Extract] Parsed candidate: text_len={}, verified={}, text_quality={:.3}, consistency={:.3}, copies={}, fallback_score={:.3}, text='{}'", 
                text.len(), verified, text_quality, consistency, copies, fallback_score, text.chars().take(20).collect::<String>());

            if fallback_score > best_fallback_score {
                best_fallback_score = fallback_score;
                best_fallback_candidate = Some(text.clone());
            }
            if verified {
                let verified_score = consistency * 0.8 + copy_score * 0.2;
                if verified_score > best_verified_score {
                    best_verified_score = verified_score;
                    best_verified_candidate = Some(text);
                }
            }
        }
    }

    (
        best_verified_candidate,
        best_verified_score,
        best_fallback_candidate,
        best_fallback_score,
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn collect_bits_by_step(
    bytes: &[u8],
    width: usize,
    height: usize,
    block_size: usize,
    step: usize,
) -> Vec<u8> {
    let y_steps: Vec<usize> = (0..height - block_size).step_by(step).collect();
    let x_steps: Vec<usize> = (0..width - block_size).step_by(step).collect();

    y_steps.par_iter().flat_map(|&y| {
        let mut row_bits = Vec::with_capacity(x_steps.len());
        for &x in &x_steps {
            let mut block = [[0.0; 8]; 8];
            for (i, row) in block.iter_mut().enumerate() {
                for (j, value) in row.iter_mut().enumerate() {
                    let idx = ((y + i) * width + (x + j)) * 4;
                    let r = bytes[idx] as f64;
                    let g = bytes[idx + 1] as f64;
                    let b = bytes[idx + 2] as f64;
                    let (y_val, _, _) = rgb_to_ycbcr(r as u8, g as u8, b as u8);
                    *value = y_val;
                }
            }
            let dwt_block = dwt2_haar_8x8(&block);
            row_bits.push(extract_bit_from_dwt_block(&dwt_block));
        }
        row_bits
    }).collect()
}

#[cfg(target_arch = "wasm32")]
fn collect_bits_by_step(
    bytes: &[u8],
    width: usize,
    height: usize,
    block_size: usize,
    step: usize,
) -> Vec<u8> {
    let mut bits = Vec::<u8>::new();
    for y in (0..height - block_size).step_by(step) {
        for x in (0..width - block_size).step_by(step) {
            let mut block = [[0.0; 8]; 8];
            for (i, row) in block.iter_mut().enumerate() {
                for (j, value) in row.iter_mut().enumerate() {
                    let idx = ((y + i) * width + (x + j)) * 4;
                    let r = bytes[idx] as f64;
                    let g = bytes[idx + 1] as f64;
                    let b = bytes[idx + 2] as f64;
                    let (y_val, _, _) = rgb_to_ycbcr(r as u8, g as u8, b as u8);
                    *value = y_val;
                }
            }
            let dwt_block = dwt2_haar_8x8(&block);
            bits.push(extract_bit_from_dwt_block(&dwt_block));
        }
    }
    bits
}

fn dwt2_haar_8x8(block: &[[f64; 8]; 8]) -> [[f64; 8]; 8] {
    let mut temp = [[0.0; 8]; 8];
    let mut out = [[0.0; 8]; 8];

    for row in 0..8 {
        for col in (0..8).step_by(2) {
            let a = (block[row][col] + block[row][col + 1]) * 0.5;
            let d = (block[row][col] - block[row][col + 1]) * 0.5;
            let idx = col / 2;
            temp[row][idx] = a;
            temp[row][idx + 4] = d;
        }
    }

    for col in 0..8 {
        for row in (0..8).step_by(2) {
            let a = (temp[row][col] + temp[row + 1][col]) * 0.5;
            let d = (temp[row][col] - temp[row + 1][col]) * 0.5;
            let idx = row / 2;
            out[idx][col] = a;
            out[idx + 4][col] = d;
        }
    }

    out
}

fn idwt2_haar_8x8(coeff: &[[f64; 8]; 8]) -> [[f64; 8]; 8] {
    let mut temp = [[0.0; 8]; 8];
    let mut out = [[0.0; 8]; 8];

    for col in 0..8 {
        for row in 0..4 {
            let a = coeff[row][col];
            let d = coeff[row + 4][col];
            temp[row * 2][col] = a + d;
            temp[row * 2 + 1][col] = a - d;
        }
    }

    for row in 0..8 {
        for col in 0..4 {
            let a = temp[row][col];
            let d = temp[row][col + 4];
            out[row][col * 2] = a + d;
            out[row][col * 2 + 1] = a - d;
        }
    }

    out
}

fn embed_bit_in_dwt_block(coeff_block: &mut [[f64; 8]; 8], bit: u8, strength: f64) {
    let pairs = [
        ((1, 5), (5, 1)),
        ((2, 6), (6, 2)),
        ((3, 4), (4, 3)),
    ];

    for ((r_a, c_a), (r_b, c_b)) in pairs {
        let a = coeff_block[r_a][c_a];
        let b = coeff_block[r_b][c_b];
        let diff = a - b;
        let target = if bit == 1 { strength } else { -strength };
        if (bit == 1 && diff < target) || (bit == 0 && diff > target) {
            let delta = ((target - diff) * 0.25).clamp(-5.0, 5.0); // 增加 clamp 范围，允许更强的嵌入
            coeff_block[r_a][c_a] += delta;
            coeff_block[r_b][c_b] -= delta;
        }
    }
}

fn extract_bit_from_dwt_block(coeff_block: &[[f64; 8]; 8]) -> u8 {
    let pairs = [
        ((1, 5), (5, 1)),
        ((2, 6), (6, 2)),
        ((3, 4), (4, 3)),
    ];
    let mut votes = 0f64;
    for ((r_a, c_a), (r_b, c_b)) in pairs {
        let diff = coeff_block[r_a][c_a] - coeff_block[r_b][c_b];
        votes += diff;
    }
    if votes > 0.0 { 1 } else { 0 }
}

/// 将 RGB 转换为 YCbCr
fn rgb_to_ycbcr(r: u8, g: u8, b: u8) -> (f64, f64, f64) {
    let r = r as f64;
    let g = g as f64;
    let b = b as f64;
    let y = 0.299 * r + 0.587 * g + 0.114 * b;
    let cb = 128.0 + (-0.168736) * r + (-0.331264) * g + 0.5 * b;
    let cr = 128.0 + 0.5 * r + (-0.418688) * g + (-0.081312) * b;
    (y, cb, cr)
}

/// 将 YCbCr 转换回 RGB
fn ycbcr_to_rgb(y: f64, cb: f64, cr: f64) -> (u8, u8, u8) {
    let r = (y + 1.402 * (cr - 128.0)).clamp(0.0, 255.0);
    let g = (y - 0.344136 * (cb - 128.0) - 0.714136 * (cr - 128.0)).clamp(0.0, 255.0);
    let b = (y + 1.772 * (cb - 128.0)).clamp(0.0, 255.0);
    (r as u8, g as u8, b as u8)
}

/// 增强版 dwt 嵌入：水印重复嵌入，只用一轮（避免多轮同步问题）
fn robust_embed(
    bytes: &[u8],
    width: usize,
    height: usize,
    watermark_text: &str,
) -> Option<Vec<u8>> {
    const BLOCK_SIZE: usize = 8;
    const STEP_CANDIDATES: [usize; 7] = [8, 6, 4, 3, 2, 1, 1]; // Fallback to 1
    const STRENGTH: f64 = 12.0; // 大幅增加基础嵌入强度

    if width <= BLOCK_SIZE || height <= BLOCK_SIZE {
        return None;
    }

    let use_v1 = watermark_text.len() <= MAX_WATERMARK_TEXT_BYTES_V1;
    let payload_bits = if use_v1 {
        let payload = build_watermark_payload_v1(watermark_text);
        payload
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
            .collect::<Vec<u8>>()
    } else {
        let payload = build_watermark_payload(watermark_text);
        payload
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
            .collect::<Vec<u8>>()
    };
    let payload_bit_count = if use_v1 {
        WATERMARK_PAYLOAD_BITS_V1
    } else {
        WATERMARK_PAYLOAD_BITS
    };
    let checksum = compute_checksum(watermark_text);
    debug!("[DWT] 嵌入水印: '{}', checksum: {}", watermark_text, checksum);

    // 极端边缘情况：720x300，即使 step=1 也只有约 3200 个块。
    // 如果我们要塞下 220 字节（1760 比特），那只能抄写不到 2 遍。
    // 为了进一步榨干空间，我们强制加入 step=1 选项，且不检查 total_blocks < payload_bit_count 就能直接跑（即使只抄半遍）
    let mut step = STEP_CANDIDATES[0];
    let mut total_blocks = 0usize;
    for &candidate in &STEP_CANDIDATES {
        // 使用与提取端完全相同的块计算方式 (0..dim - block_size).step_by(step) 的长度
        let blocks_x = (0..width - BLOCK_SIZE).step_by(candidate).count();
        let blocks_y = (0..height - BLOCK_SIZE).step_by(candidate).count();
        let blocks = blocks_x * blocks_y;
        if blocks >= payload_bit_count {
            step = candidate;
            total_blocks = blocks;
            break;
        }
        if blocks > total_blocks {
            total_blocks = blocks;
            step = candidate;
        }
    }
    
    // 如果最高密度（step=1）都写不下一遍，那就直接用最高密度硬写
    if total_blocks < payload_bit_count {
        step = 1;
        let blocks_x = (0..width - BLOCK_SIZE).step_by(step).count();
        let blocks_y = (0..height - BLOCK_SIZE).step_by(step).count();
        total_blocks = blocks_x * blocks_y;
    }
    // 移除对 total_blocks < payload_bit_count 的硬性拦截
    // 因为即使空间不够写完整一遍，能写多少是多少，有几率配合其他通道或者局部完整性被解析出来。
    if total_blocks == 0 {
        return None;
    }
    debug!(
        "[DWT] embed size={}x{}, step={}, payload_bits={}, blocks={}",
        width,
        height,
        step,
        payload_bit_count,
        total_blocks
    );
    let mut output = bytes.to_vec();
    let mut bit_index = 0usize;

    for y in (0..height - BLOCK_SIZE).step_by(step) {
        for x in (0..width - BLOCK_SIZE).step_by(step) {
            let bit = payload_bits[bit_index % payload_bit_count];
            let mut block = [[0.0; 8]; 8];

            // 提取 Y 通道
            for (i, row) in block.iter_mut().enumerate() {
                for (j, value) in row.iter_mut().enumerate() {
                    let idx = ((y + i) * width + (x + j)) * 4;
                    let r = output[idx] as f64;
                    let g = output[idx + 1] as f64;
                    let b = output[idx + 2] as f64;
                    let (y_val, _, _) = rgb_to_ycbcr(r as u8, g as u8, b as u8);
                    *value = y_val;
                }
            }

            let mut mean = 0.0;
            for row in &block {
                for value in row {
                    mean += *value;
                }
            }
            mean /= 64.0;
            let mut variance = 0.0;
            for row in &block {
                for value in row {
                    let d = *value - mean;
                    variance += d * d;
                }
            }
            variance /= 64.0;
            // 降低自适应强度的门槛，让边缘或平滑区域也强制写入更高的强度，防止提取时被破坏
            let adapt = (variance / 180.0).clamp(1.0, 2.0); // 进一步提升适应系数下限
            let effective_strength = STRENGTH * adapt;

            let mut dwt_block = dwt2_haar_8x8(&block);
            embed_bit_in_dwt_block(&mut dwt_block, bit, effective_strength);
            let idwt_block = idwt2_haar_8x8(&dwt_block);

            // 写回 Y 通道
            for (i, row) in block.iter().enumerate() {
                for (j, old_y) in row.iter().enumerate() {
                    let idx = ((y + i) * width + (x + j)) * 4;
                    let new_y = idwt_block[i][j].clamp(0.0, 255.0);
                    let diff = new_y - *old_y;

                    let old_r = output[idx] as f64;
                    let old_g = output[idx + 1] as f64;
                    let old_b = output[idx + 2] as f64;

                    let (y_old, cb, cr) = rgb_to_ycbcr(old_r as u8, old_g as u8, old_b as u8);
                    let y_new = (y_old + diff).clamp(0.0, 255.0);
                    let (r, g, b) = ycbcr_to_rgb(y_new, cb, cr);

                    output[idx] = r;
                    output[idx + 1] = g;
                    output[idx + 2] = b;
                }
            }

            bit_index += 1;
        }
    }

    Some(output)
}

/// 从带水印图片中提取文本
fn robust_extract(
    bytes: &[u8],
    width: usize,
    height: usize,
) -> Option<String> {
    const BLOCK_SIZE: usize = 8;
    const STEPS: [usize; 8] = [12, 8, 6, 4, 3, 2, 1, 1]; // 增加更多容错步长

    if width <= BLOCK_SIZE || height <= BLOCK_SIZE {
        return None;
    }

    let evaluate_step = |step: usize| -> (Option<String>, f64, Option<String>, f64) {
        let bits = collect_bits_by_step(bytes, width, height, BLOCK_SIZE, step);
        if bits.is_empty() {
            return (None, 0.0, None, 0.0);
        }
        
        // --- ADDED DEBUGGING FOR BITS EXTRACTION ---
        debug!("[DWT Extract] step={}, total_bits_extracted={}", step, bits.len());

        let (best_verified_candidate_v2, best_verified_score_v2, best_fallback_candidate_v2, best_fallback_score_v2) =
            evaluate_payload_candidates(
                &bits,
                WATERMARK_PAYLOAD_BITS,
                WATERMARK_PAYLOAD_BYTES,
                parse_watermark_payload,
            );
        let (best_verified_candidate_v1, best_verified_score_v1, best_fallback_candidate_v1, best_fallback_score_v1) =
            evaluate_payload_candidates(
                &bits,
                WATERMARK_PAYLOAD_BITS_V1,
                WATERMARK_PAYLOAD_BYTES_V1,
                parse_watermark_payload_v1,
            );

        let (step_verified_candidate, step_verified_score) =
            if best_verified_score_v2 >= best_verified_score_v1 {
                (best_verified_candidate_v2, best_verified_score_v2)
            } else {
                (best_verified_candidate_v1, best_verified_score_v1)
            };
        let (step_fallback_candidate, step_fallback_score) =
            if best_fallback_score_v2 >= best_fallback_score_v1 {
                (best_fallback_candidate_v2, best_fallback_score_v2)
            } else {
                (best_fallback_candidate_v1, best_fallback_score_v1)
            };

        (
            step_verified_candidate,
            step_verified_score,
            step_fallback_candidate,
            step_fallback_score,
        )
    };

    let mut best_verified_candidate: Option<String> = None;
    let mut best_verified_score = 0.0f64;
    let mut best_fallback_candidate: Option<String> = None;
    let mut best_fallback_score = 0.0f64;

    #[cfg(not(target_arch = "wasm32"))]
    {
        // 按顺序评估，如果发现非常确定的水印（verified），就立刻停止，极大节省大图时间
        for &step in &STEPS {
            let (step_verified_candidate, step_verified_score, step_fallback_candidate, step_fallback_score) = evaluate_step(step);
            
            if step_verified_score > best_verified_score {
                best_verified_score = step_verified_score;
                best_verified_candidate = step_verified_candidate;
            }
            if step_fallback_score > best_fallback_score {
                best_fallback_score = step_fallback_score;
                best_fallback_candidate = step_fallback_candidate;
            }
            
            // 如果分数极高（比如验证通过且分数 >= 0.8），直接提前结束，不浪费时间算更小的 step
            if best_verified_score >= 0.8 {
                debug!("[DWT] Early exit at step {} with high verified score: {:.3}", step, best_verified_score);
                break;
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        for step in STEPS {
            let (step_verified_candidate, step_verified_score, step_fallback_candidate, step_fallback_score) =
                evaluate_step(step);
            if step_verified_score > best_verified_score {
                best_verified_score = step_verified_score;
                best_verified_candidate = step_verified_candidate;
            }
            if step_fallback_score > best_fallback_score {
                best_fallback_score = step_fallback_score;
                best_fallback_candidate = step_fallback_candidate;
            }
        }
    }

    if best_verified_candidate.is_none() && best_fallback_candidate.is_none() {
        return Some("未检测到水印".to_string());
    }

    debug!(
        "[DWT] strict score={:.3}, fallback score={:.3}",
        best_verified_score,
        best_fallback_score
    );

    if best_verified_score >= 0.26 {
        return best_verified_candidate;
    }
    if best_fallback_score >= 0.7 {
        return best_fallback_candidate.map(|value| format!("疑似水印: {}", value));
    }
    Some("未检测到水印".to_string())
}

// ==================== 公开 API ====================

/// 获取嵌入后的水印文本字节数（用于告知提取端需要提取多少比特）
pub fn get_watermark_byte_count(text: &str) -> usize {
    let _ = text;
    WATERMARK_PAYLOAD_BYTES
}

pub fn dwt_embed_to_rgba(
    bytes: &[u8],
    width: usize,
    height: usize,
    watermark_text: &str,
) -> Option<Vec<u8>> {
    robust_embed(bytes, width, height, watermark_text)
}

pub fn dwt_embed_to_bgra(
    bytes: &[u8],
    width: usize,
    height: usize,
    watermark_text: &str,
) -> Option<Vec<u8>> {
    robust_embed(bytes, width, height, watermark_text)
}

pub fn dwt_extract_from_rgba(bytes: &[u8], width: usize, height: usize) -> Option<String> {
    robust_extract(bytes, width, height)
}

pub fn dwt_extract_from_bgra(bytes: &[u8], width: usize, height: usize) -> Option<String> {
    robust_extract(bytes, width, height)
}
