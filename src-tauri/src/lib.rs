use std::time::Instant;
use image::ImageEncoder;

#[derive(serde::Serialize)]
pub struct EmbedResult {
    pub image_bytes: Vec<u8>,
    pub wm_size: usize,
    pub duration_ms: f64,
    pub mime_type: String,
}

#[derive(serde::Serialize)]
pub struct ExtractResult {
    pub watermark_text: String,
    pub duration_ms: f64,
}

const DEFAULT_PASSWORD_IMG: u64 = 123456;
const DEFAULT_PASSWORD_WM: u64 = 123456;

#[tauri::command]
async fn embed_watermark(
    image_bytes: Vec<u8>,
    watermark_text: String,
    format: String,
) -> Result<EmbedResult, String> {
    tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let image = image::load_from_memory(&image_bytes)
            .map_err(|e| format!("图片解码失败: {}", e))?;
        let rgba = image.to_rgba8();
        let width = rgba.width() as usize;
        let height = rgba.height() as usize;

        let (embedded, wm_size) = dwt_watermark_core::blind_watermark::blind_embed(
            rgba.as_raw(), width, height, &watermark_text,
            DEFAULT_PASSWORD_IMG, DEFAULT_PASSWORD_WM,
        ).ok_or("水印嵌入失败")?;

        let (out, mime_type) = if format == "jpeg" {
            let mut out = Vec::new();
            let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 92);
            let rgb: Vec<u8> = embedded.chunks_exact(4).flat_map(|c| [c[0], c[1], c[2]]).collect();
            encoder.write_image(&rgb, width as u32, height as u32, image::ExtendedColorType::Rgb8)
                .map_err(|e| format!("JPEG 编码失败: {}", e))?;
            (out, "image/jpeg".to_string())
        } else {
            let mut out = Vec::new();
            let encoder = image::codecs::png::PngEncoder::new_with_quality(
                &mut out,
                image::codecs::png::CompressionType::Default,
                image::codecs::png::FilterType::NoFilter,
            );
            encoder.write_image(&embedded, width as u32, height as u32, image::ExtendedColorType::Rgba8)
                .map_err(|e| format!("PNG 编码失败: {}", e))?;
            (out, "image/png".to_string())
        };

        Ok(EmbedResult {
            image_bytes: out,
            wm_size,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            mime_type,
        })
    })
    .await
    .map_err(|e| format!("任务执行失败: {}", e))?
}

#[tauri::command]
async fn extract_watermark(
    image_bytes: Vec<u8>,
    wm_size: usize,
) -> Result<ExtractResult, String> {
    tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let image = image::load_from_memory(&image_bytes)
            .map_err(|e| format!("图片解码失败: {}", e))?;
        let rgba = image.to_rgba8();
        let width = rgba.width() as usize;
        let height = rgba.height() as usize;

        let text = dwt_watermark_core::blind_watermark::blind_extract(
            rgba.as_raw(), width, height, wm_size,
            DEFAULT_PASSWORD_IMG, DEFAULT_PASSWORD_WM,
        ).unwrap_or_else(|| "未检测到水印".to_string());

        Ok(ExtractResult {
            watermark_text: text,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
        })
    })
    .await
    .map_err(|e| format!("任务执行失败: {}", e))?
}

#[tauri::command]
fn save_file(path: String, data: Vec<u8>) -> Result<(), String> {
    std::fs::write(&path, data).map_err(|e| format!("保存文件失败: {}", e))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![embed_watermark, extract_watermark, save_file])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
