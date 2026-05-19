const fs = require('fs')
const path = require('path')

const rootPkgPath = path.resolve('package.json')
const rootPkg = JSON.parse(fs.readFileSync(rootPkgPath, 'utf8'))
const version = rootPkg.version

const npmDir = path.resolve('npm')
const optionalDeps = {}

// 复制 artifacts 中的 .node 文件到对应 npm/ 子目录
const artifactsDir = path.resolve('artifacts')
if (fs.existsSync(artifactsDir)) {
  for (const artifactDir of fs.readdirSync(artifactsDir)) {
    const artifactPath = path.join(artifactsDir, artifactDir)
    if (!fs.statSync(artifactPath).isDirectory()) continue

    for (const file of fs.readdirSync(artifactPath)) {
      if (!file.endsWith('.node')) continue
      // watermark.win32-x64-msvc.node → win32-x64-msvc
      const platform = file.replace(/^watermark\./, '').replace(/\.node$/, '')
      const targetDir = path.join(npmDir, platform)
      if (fs.existsSync(targetDir)) {
        fs.copyFileSync(path.join(artifactPath, file), path.join(targetDir, file))
        console.log(`Copied ${file} → npm/${platform}/`)
      }
    }
  }
}

// 同步所有子包的版本号，并收集 optionalDependencies
for (const dir of fs.readdirSync(npmDir)) {
  const pkgPath = path.join(npmDir, dir, 'package.json')
  if (!fs.existsSync(pkgPath)) continue

  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
  pkg.version = version
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n')

  optionalDeps[pkg.name] = version
  console.log(`Synced ${pkg.name} → ${version}`)
}

// 写入主包的 optionalDependencies
rootPkg.optionalDependencies = optionalDeps
fs.writeFileSync(rootPkgPath, JSON.stringify(rootPkg, null, 2) + '\n')
console.log(`Updated optionalDependencies in root package.json`)
