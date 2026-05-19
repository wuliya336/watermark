use dwt_watermark_core::blind_watermark::{blind_embed, blind_extract};

#[test]
fn test_blind_roundtrip() {
    let width = 1440;
    let height = 3000;
    let pixel_count = width * height;
    let mut rgba = vec![0u8; pixel_count * 4];
    for i in 0..pixel_count {
        rgba[i * 4] = (i % 256) as u8;
        rgba[i * 4 + 1] = ((i / 256) % 256) as u8;
        rgba[i * 4 + 2] = ((i / 65536) % 256) as u8;
        rgba[i * 4 + 3] = 255;
    }

    let watermark = r#"{"a":1715424000000,"b":"v1.0.0","c":"user123"}"#;

    let embed_start = std::time::Instant::now();
    let (embedded, wm_size) = blind_embed(&rgba, width, height, watermark, 123456, 123456
    ).unwrap();
    let embed_time = embed_start.elapsed().as_secs_f64() * 1000.0;
    println!("Embed: width={} height={} -> {} ms", width, height, embed_time);

    let extract_start = std::time::Instant::now();
    let extracted = blind_extract(&embedded, width, height, wm_size, 123456, 123456
    ).unwrap();
    let extract_time = extract_start.elapsed().as_secs_f64() * 1000.0;
    println!("Extract: width={} height={} -> {} ms", width, height, extract_time);

    assert_eq!(extracted, watermark, "提取水印应与原始水印一致");
    println!("水印长度: {} bits ({} 字节)", wm_size, wm_size / 8);
}

#[test]
fn test_blind_small() {
    let width = 512;
    let height = 512;
    let pixel_count = width * height;
    let mut rgba = vec![0u8; pixel_count * 4];
    for i in 0..pixel_count {
        rgba[i * 4] = 128;
        rgba[i * 4 + 1] = 64;
        rgba[i * 4 + 2] = 200;
        rgba[i * 4 + 3] = 255;
    }

    let watermark = "test watermark";

    let embed_start = std::time::Instant::now();
    let (embedded, wm_size) = blind_embed(&rgba, width, height, watermark, 123456, 123456
    ).unwrap();
    let embed_time = embed_start.elapsed().as_secs_f64() * 1000.0;
    println!("Small Embed: {}x{} -> {} ms", width, height, embed_time);

    let extract_start = std::time::Instant::now();
    let extracted = blind_extract(&embedded, width, height, wm_size, 123456, 123456
    ).unwrap();
    let extract_time = extract_start.elapsed().as_secs_f64() * 1000.0;
    println!("Small Extract: {}x{} -> {} ms", width, height, extract_time);

    assert_eq!(extracted, watermark);
}

#[test]
fn test_large_image() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = std::path::Path::new(&manifest_dir)
        .parent().unwrap()
        .parent().unwrap();
    let test_path = project_root.join("test.jpg");
    let bytes = std::fs::read(&test_path).expect("读取 test.jpg 失败");
    let img = image::load_from_memory(&bytes).expect("解码 test.jpg 失败");
    let rgba = img.to_rgba8();
    let width = rgba.width() as usize;
    let height = rgba.height() as usize;
    let rgba_bytes = rgba.as_raw();

    println!("图片尺寸: {}x{} ({} 像素)", width, height, width * height);

    let watermark = r#"{"a":1715424000000,"b":"v1.0.0","c":"user123"}"#;

    let embed_start = std::time::Instant::now();
    let (embedded, wm_size) = blind_embed(
        rgba_bytes, width, height, watermark, 123456, 123456
    ).expect("嵌入失败");
    let embed_time = embed_start.elapsed().as_secs_f64() * 1000.0;
    println!("Embed: {}x{} -> {} ms", width, height, embed_time);

    let extract_start = std::time::Instant::now();
    let extracted = blind_extract(&embedded, width, height, wm_size, 123456, 123456
    ).expect("提取失败");
    let extract_time = extract_start.elapsed().as_secs_f64() * 1000.0;
    println!("Extract: {}x{} -> {} ms", width, height, extract_time);

    assert_eq!(extracted, watermark);
}
