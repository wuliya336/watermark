use image::ImageEncoder;
use napi::bindgen_prelude::{Buffer, Error, Result};
use napi_derive::napi;

#[napi(object)]
pub struct EmbedOutput {
    pub buffer: Buffer,
    pub wm_size: u32,
}

#[napi]
pub fn embed_watermark_to_png_bytes(
    image_bytes: Buffer,
    watermark_text: String,
) -> Result<EmbedOutput> {
    let image = image::load_from_memory(image_bytes.as_ref())
        .map_err(|e| Error::from_reason(format!("图片解码失败: {e}")))?;
    let rgba = image.to_rgba8();
    let width = rgba.width() as usize;
    let height = rgba.height() as usize;

    let (embedded, wm_size) = dwt_watermark_core::blind_watermark::blind_embed(
        rgba.as_raw(), width, height, &watermark_text, 123456, 123456,
    ).ok_or_else(|| Error::from_reason("水印嵌入失败"))?;

    let mut out = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new_with_quality(
        &mut out,
        image::codecs::png::CompressionType::Default,
        image::codecs::png::FilterType::NoFilter,
    );
    encoder
        .write_image(
            &embedded,
            width as u32,
            height as u32,
            image::ExtendedColorType::Rgba8,
        )
        .map_err(|e| Error::from_reason(format!("PNG 编码失败: {e}")))?;

    Ok(EmbedOutput {
        buffer: Buffer::from(out),
        wm_size: wm_size as u32,
    })
}

#[napi]
pub fn extract_watermark_from_png_bytes(
    image_bytes: Buffer,
    wm_size: u32,
) -> Result<String> {
    let image = image::load_from_memory(image_bytes.as_ref())
        .map_err(|e| Error::from_reason(format!("图片解码失败: {e}")))?;
    let rgba = image.to_rgba8();
    let width = rgba.width() as usize;
    let height = rgba.height() as usize;

    let text = dwt_watermark_core::blind_watermark::blind_extract(
        rgba.as_raw(), width, height, wm_size as usize, 123456, 123456,
    ).unwrap_or_else(|| "未检测到水印".to_string());

    Ok(text)
}
