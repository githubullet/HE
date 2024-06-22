package main

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"hash/fnv"
	"image"
	"image/color"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"

	_ "golang.org/x/image/bmp"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
	"golang.org/x/image/bmp"
)

var (
	params    ckks.Parameters
	encoder   ckks.Encoder
	encryptor rlwe.Encryptor
	decryptor rlwe.Decryptor
	evaluator ckks.Evaluator

	paramsCache  sync.Map
	keyPairCache sync.Map
)

// HashableParameters is a wrapper for ckks.Parameters to make it hashable
type HashableParameters struct {
	params ckks.Parameters
}

func (h HashableParameters) Hash() uint64 {
	hasher := fnv.New64a()
	hasher.Write([]byte(fmt.Sprintf("%v", h.params)))
	return hasher.Sum64()
}

// PRNGWrapper 包装一个PRNG,并添加一个使用计数器
type PRNGWrapper struct {
	prng  utils.PRNG
	count int
	limit int
	seed  []byte
}

func NewPRNGWrapper(seed []byte, limit int) (*PRNGWrapper, error) {
	prng, err := utils.NewKeyedPRNG(seed)
	if err != nil {
		return nil, err
	}
	return &PRNGWrapper{prng: prng, count: 0, limit: limit, seed: seed}, nil
}

func (p *PRNGWrapper) Read(b []byte) (n int, err error) {
	if p.count >= p.limit {
		log.Println("Resetting PRNG")
		prng, err := utils.NewKeyedPRNG(p.seed)
		if err != nil {
			log.Println("PRNG reset failed:", err)
			return 0, err
		}
		p.prng = prng
		p.count = 0
	}
	n, err = p.prng.Read(b)
	if err != nil {
		log.Println("PRNG read error:", err)
	}
	p.count++
	return
}

func getCKKSParams(literal ckks.ParametersLiteral) (ckks.Parameters, error) {
	key := fmt.Sprintf("%v", literal)
	if cachedParams, ok := paramsCache.Load(key); ok {
		return cachedParams.(ckks.Parameters), nil
	}
	params, err := ckks.NewParametersFromLiteral(literal)
	if err != nil {
		return ckks.Parameters{}, err
	}
	paramsCache.Store(key, params)
	return params, nil
}

func getKeyPair(params ckks.Parameters) (*rlwe.SecretKey, *rlwe.PublicKey) {
	hashable := HashableParameters{params}
	key := hashable.Hash()
	if cachedKeyPair, ok := keyPairCache.Load(key); ok {
		keyPair := cachedKeyPair.([2]interface{})
		return keyPair[0].(*rlwe.SecretKey), keyPair[1].(*rlwe.PublicKey)
	}
	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	keyPairCache.Store(key, [2]interface{}{sk, pk})
	return sk, pk
}

func getRotationKeys(params ckks.Parameters, sk *rlwe.SecretKey, width, height, filterSize int) *rlwe.RotationKeySet {
	pad := filterSize / 2
	rotations := make([]int, 0, (2*pad+1)*(2*pad+1)-1)
	for dy := -pad; dy <= pad; dy++ {
		for dx := -pad; dx <= pad; dx++ {
			if dx == 0 && dy == 0 {
				continue
			}
			rotations = append(rotations, dy*width+dx)
		}
	}

	key := fmt.Sprintf("rotkeys_%v_%d_%d_%d", params, width, height, filterSize)
	if cachedKeys, ok := keyPairCache.Load(key); ok {
		return cachedKeys.(*rlwe.RotationKeySet)
	}
	kgen := ckks.NewKeyGenerator(params)
	rotKeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	keyPairCache.Store(key, rotKeys)
	return rotKeys
}

var plaintextPool = sync.Pool{
	New: func() interface{} {
		return ckks.NewPlaintext(params, params.MaxLevel())
	},
}

func init() {
	var err error
	params, err = ckks.NewParametersFromLiteral(ckks.PN12QP109)
	if err != nil {
		log.Fatal(err)
	}
	encoder = ckks.NewEncoder(params)
	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encryptor = ckks.NewEncryptor(params, pk)
	decryptor = ckks.NewDecryptor(params, sk)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func bmpRead(filename string) (image.Image, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		return nil, err
	}

	return img, nil
}

func bmpWrite(filename string, img image.Image) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outFile.Close()

	err = bmp.Encode(outFile, img)
	if err != nil {
		return err
	}

	return nil
}

func pixelToArray(img image.Image, startX, startY, width, height int) [][]float64 {
	ret := make([][]float64, height)
	for y := 0; y < height; y++ {
		ret[y] = make([]float64, width*3)
		for x := 0; x < width; x++ {
			r, g, b, _ := img.At(startX+x, startY+y).RGBA()
			ret[y][x*3] = float64(r >> 8)
			ret[y][x*3+1] = float64(g >> 8)
			ret[y][x*3+2] = float64(b >> 8)
		}
	}
	return ret
}

func arrayToImage(arr [][]float64, startX, startY, width, height int, img *image.RGBA) {
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r := uint8(math.Max(0, math.Min(255, arr[y][x*3])))
			g := uint8(math.Max(0, math.Min(255, arr[y][x*3+1])))
			b := uint8(math.Max(0, math.Min(255, arr[y][x*3+2])))
			img.Set(startX+x, startY+y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
}

func encryptPixel(ciphertext *rlwe.Ciphertext, params ckks.Parameters,
	encoder ckks.Encoder, encryptor rlwe.Encryptor, prngWrapper *PRNGWrapper,
	pixelValue float64) {
	plaintext := plaintextPool.Get().(*rlwe.Plaintext)
	encoder.Encode([]float64{pixelValue}, plaintext, params.LogSlots())
	encryptor.Encrypt(plaintext, ciphertext)
	plaintextPool.Put(plaintext)
}

func decryptPixel(ciphertext *rlwe.Ciphertext, params ckks.Parameters,
	encoder ckks.Encoder, decryptor rlwe.Decryptor, prngWrapper *PRNGWrapper) float64 {
	plaintext := plaintextPool.Get().(*rlwe.Plaintext)
	decryptor.Decrypt(ciphertext, plaintext)
	res := encoder.Decode(plaintext, params.LogSlots())
	plaintextPool.Put(plaintext)
	return real(res[0]) + imag(res[0]) // 考虑实部和虚部
}

func saveEncryptedPixels(filepath string, blockHeight, blockWidth int, encryptedPixels [][]*rlwe.Ciphertext) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	err = encoder.Encode(blockHeight)
	if err != nil {
		return err
	}
	err = encoder.Encode(blockWidth)
	if err != nil {
		return err
	}
	err = encoder.Encode(encryptedPixels)
	if err != nil {
		return err
	}

	return nil
}

func loadEncryptedPixels(filepath string) (int, int, [][]*rlwe.Ciphertext, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return 0, 0, nil, err
	}
	defer file.Close()

	var blockHeight, blockWidth int
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&blockHeight)
	if err != nil {
		return 0, 0, nil, err
	}
	err = decoder.Decode(&blockWidth)
	if err != nil {
		return 0, 0, nil, err
	}
	var encryptedPixels [][]*rlwe.Ciphertext
	err = decoder.Decode(&encryptedPixels)
	if err != nil {
		return 0, 0, nil, err
	}

	return blockHeight, blockWidth, encryptedPixels, nil
}

func applyMeanFilter(ciphertext *rlwe.Ciphertext, width, height, filterSize int, params ckks.Parameters, evaluator ckks.Evaluator, encoder ckks.Encoder, encryptor rlwe.Encryptor) *rlwe.Ciphertext {
	pad := filterSize / 2

	// 创建一个密文副本来应用滤波器
	result := ciphertext.CopyNew()

	// 使用同态加法应用均值滤波器
	for dy := -pad; dy <= pad; dy++ {
		for dx := -pad; dx <= pad; dx++ {
			if dx == 0 && dy == 0 {
				continue
			}
			shifted := evaluator.RotateNew(ciphertext, dy*width+dx)
			result = evaluator.AddNew(result, shifted)
		}
	}

	// 不再进行除法操作
	return result
}

func main() {
	// 设置图片和密文文件保存的路径
	imageFilePath := "kingfisher.bmp"
	encryptedFilesDir := "./encrypted_blocks"
	os.MkdirAll(encryptedFilesDir, os.ModePerm)

	// 加密图片并保存密文
	encryptImageAndSaveCiphertext(imageFilePath, encryptedFilesDir)

	// 从密文文件解密并生成图片
	decryptCiphertextAndGenerateImage(imageFilePath, encryptedFilesDir)
}

func encryptImageAndSaveCiphertext(imageFilePath, encryptedFilesDir string) {
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	logMemoryUsage("Start of Program")

	// 创建CPU profile文件
	cpuProfile, err := os.Create("cpu_profile.prof")
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	defer cpuProfile.Close()

	// 开始CPU profiling
	if err := pprof.StartCPUProfile(cpuProfile); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()

	start := time.Now().UnixMicro()
	img, err := bmpRead(imageFilePath)
	if err != nil {
		log.Fatal("Failed to read image:", err)
	}
	end := time.Now().UnixMicro()
	logMemoryUsage("After Reading Image")
	fmt.Printf("ScanPic     : %8d μs\n", end-start)
	fmt.Printf("Resolution : %4d x%4d\n", img.Bounds().Max.X, img.Bounds().Max.Y)

	// 创建 PRNGWrapper
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		log.Fatalf("failed to generate seed: %v", err)
	}
	prngWrapper, err := NewPRNGWrapper(seed, 100000000)
	if err != nil {
		log.Fatal(err)
	}

	start = time.Now().UnixMicro()
	params, err = getCKKSParams(ckks.PN12QP109)
	check(err)
	encoder := ckks.NewEncoder(params)

	sk, pk := getKeyPair(params)
	encryptor := ckks.NewEncryptor(params, pk)
	rlk := ckks.NewKeyGenerator(params).GenRelinearizationKey(sk, 1) // 生成重线性化密钥
	end = time.Now().UnixMicro()
	logMemoryUsage("After Setup")
	fmt.Printf("Setup       : %8d μs\n", end-start)

	height := img.Bounds().Max.Y
	width := img.Bounds().Max.X

	// 打印原始图像的像素值
	parray := pixelToArray(img, 0, 0, width, height)
	fmt.Println("Original Image Pixels:")
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			fmt.Printf("%3.0f %3.0f %3.0f  ", parray[y][x*3], parray[y][x*3+1], parray[y][x*3+2])
		}
		fmt.Println()
	}

	// Define the block size
	blockSize := 3
	// 存储加密后的密文文件名
	encryptedPixelFiles := make([][]string, (height+blockSize-1)/blockSize)
	for i := range encryptedPixelFiles {
		encryptedPixelFiles[i] = make([]string, (width+blockSize-1)/blockSize)
	}

	encStart := time.Now().UnixMicro()
	for startY := 0; startY < height; startY += blockSize {
		for startX := 0; startX < width; startX += blockSize {
			blockHeight := min(blockSize, height-startY)
			blockWidth := min(blockSize, width-startX)

			parray := pixelToArray(img, startX, startY, blockWidth, blockHeight)
			logMemoryUsage("After Converting Pixel to Array")

			encryptedPixels := make([][]*rlwe.Ciphertext, blockHeight)
			ciphertext := ckks.NewCiphertext(params, 1, params.MaxLevel())
			for i := 0; i < blockHeight; i++ {
				encryptedPixels[i] = make([]*rlwe.Ciphertext, blockWidth*3)
				for j := 0; j < blockWidth*3; j++ {
					encryptPixel(
						ciphertext, params, encoder, encryptor,
						prngWrapper, parray[i][j],
					)
					encryptedPixels[i][j] = ciphertext.CopyNew()
				}
			}
			logMemoryUsage("After Encryption")

			// 存储密文到文件
			filename := filepath.Join(encryptedFilesDir, fmt.Sprintf("encrypted_block_%d_%d.gob", startY/blockSize, startX/blockSize))
			err = saveEncryptedPixels(filename, blockHeight, blockWidth, encryptedPixels)
			if err != nil {
				log.Fatal("Failed to save encrypted pixels:", err)
			}
			encryptedPixelFiles[startY/blockSize][startX/blockSize] = filename

			// 释放加密像素内存
			for i := range encryptedPixels {
				for j := range encryptedPixels[i] {
					encryptedPixels[i][j] = nil
				}
				encryptedPixels[i] = nil
			}
			encryptedPixels = nil
		}
	}
	encEnd := time.Now().UnixMicro()
	fmt.Printf("Encryption  : %8d μs\n", encEnd-encStart)

	// 对每个加密块应用均值滤波并保存结果
	for startY := 0; startY < height; startY += blockSize {
		for startX := 0; startX < width; startX += blockSize {
			blockHeight := min(blockSize, height-startY)
			blockWidth := min(blockSize, width-startX)

			// 为当前分块生成旋转密钥
			rotKeys := getRotationKeys(params, sk, blockWidth, blockHeight, 3)
			evaluator = ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotKeys}) // 包含重线性化密钥

			// 从文件加载密文
			filename := filepath.Join(encryptedFilesDir, fmt.Sprintf("encrypted_block_%d_%d.gob", startY/blockSize, startX/blockSize))
			loadedBlockHeight, loadedBlockWidth, encryptedPixels, err := loadEncryptedPixels(filename)
			if err != nil {
				log.Fatal("Failed to load encrypted pixels:", err)
			}

			// 检查加载的密文块的大小是否正确
			if loadedBlockHeight != blockHeight || loadedBlockWidth != blockWidth {
				log.Fatalf("Incorrect block size: expected %dx%d, got %dx%d", blockHeight, blockWidth, loadedBlockHeight, loadedBlockWidth)
			}

			filterSize := 3
			for i := 0; i < blockHeight; i++ {
				for j := 0; j < blockWidth*3; j++ {
					encryptedPixels[i][j] = applyMeanFilter(encryptedPixels[i][j], blockWidth, blockHeight, filterSize, params, evaluator, encoder, encryptor)
				}
			}

			// 保存滤波后的密文到文件
			filteredFilename := filepath.Join(encryptedFilesDir, fmt.Sprintf("filtered_block_%d_%d.gob", startY/blockSize, startX/blockSize))
			err = saveEncryptedPixels(filteredFilename, blockHeight, blockWidth, encryptedPixels)
			if err != nil {
				log.Fatal("Failed to save filtered encrypted pixels:", err)
			}
		}
	}
}

func decryptCiphertextAndGenerateImage(imageFilePath, encryptedFilesDir string) {
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	logMemoryUsage("Start of Decryption")

	// 创建 PRNGWrapper
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		log.Fatalf("failed to generate seed: %v", err)
	}
	prngWrapper, err := NewPRNGWrapper(seed, 100000000)
	if err != nil {
		log.Fatal(err)
	}

	start := time.Now().UnixMicro()
	params, err := getCKKSParams(ckks.PN12QP109)
	check(err)
	encoder := ckks.NewEncoder(params)

	sk, _ := getKeyPair(params)
	decryptor := ckks.NewDecryptor(params, sk)
	end := time.Now().UnixMicro()
	logMemoryUsage("After Setup")
	fmt.Printf("Setup       : %8d μs\n", end-start)

	// Read the original image to get its dimensions
	img, err := bmpRead(imageFilePath)
	if err != nil {
		log.Fatal("Failed to read image:", err)
	}
	height := img.Bounds().Max.Y
	width := img.Bounds().Max.X

	// Define the block size
	blockSize := 3
	// Create a new RGBA image to store the processed image
	processedImg := image.NewRGBA(image.Rect(0, 0, width, height))

	filterSize := 3
	normalizationFactor := 1.0 / float64(filterSize*filterSize)

	decStart := time.Now().UnixMicro()
	for startY := 0; startY < height; startY += blockSize {
		for startX := 0; startX < width; startX += blockSize {
			blockHeight := min(blockSize, height-startY)
			blockWidth := min(blockSize, width-startX)

			// 从文件加载去噪后的密文
			filteredFilename := filepath.Join(encryptedFilesDir, fmt.Sprintf("filtered_block_%d_%d.gob", startY/blockSize, startX/blockSize))
			loadedBlockHeight, loadedBlockWidth, encryptedPixels, err := loadEncryptedPixels(filteredFilename)
			if err != nil {
				log.Fatal("Failed to load filtered encrypted pixels:", err)
			}

			// 检查加载的密文块的大小是否正确
			if loadedBlockHeight != blockHeight || loadedBlockWidth != blockWidth {
				log.Fatalf("Incorrect block size: expected %dx%d, got %dx%d", blockHeight, blockWidth, loadedBlockHeight, loadedBlockWidth)
			}

			decbody := make([][][]float64, blockHeight)
			for i := 0; i < blockHeight; i++ {
				decbody[i] = make([][]float64, blockWidth)
				for j := 0; j < blockWidth; j++ {
					decbody[i][j] = make([]float64, 3)
					for k := 0; k < 3; k++ {
						// 解密后进行归一化
						decbody[i][j][k] = decryptPixel(
							encryptedPixels[i][j*3+k], params, encoder, decryptor, prngWrapper,
						) * normalizationFactor
					}
				}
			}

			// 将三维数组转换为二维数组
			decbody2d := make([][]float64, blockHeight)
			for i := 0; i < blockHeight; i++ {
				decbody2d[i] = make([]float64, blockWidth*3)
				for j := 0; j < blockWidth; j++ {
					for k := 0; k < 3; k++ {
						decbody2d[i][j*3+k] = decbody[i][j][k]
					}
				}
			}

			arrayToImage(decbody2d, startX, startY, blockWidth, blockHeight, processedImg)
		}
	}
	decEnd := time.Now().UnixMicro()
	fmt.Printf("Decryption  : %8d μs\n", decEnd-decStart)

	// 对图像进行后处理，将像素值归一化到 0-255
	normalizeImage(processedImg)

	if err := bmpWrite("kingfisher_denoised.bmp", processedImg); err != nil {
		log.Fatal("Failed to write image:", err)
	}

	// 比较解密后的图像和原图
	originalGray := convertToGray(img)
	decryptedGray := convertToGray(processedImg)
	if compareImages(originalGray, decryptedGray) {
		fmt.Println("Images are similar")
	} else {
		fmt.Println("Images are not similar")
	}

	// 创建内存profile文件
	memProfile, err := os.Create("mem_profile.prof")
	if err != nil {
		log.Fatal("could not create memory profile: ", err)
	}
	defer memProfile.Close()

	// 获取当前的内存信息
	runtime.GC()
	if err := pprof.WriteHeapProfile(memProfile); err != nil {
		log.Fatal("could not write memory profile: ", err)
	}

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	fmt.Printf("Total Alloc = %v MB\n", bToMB(m1.TotalAlloc))
	fmt.Printf("Total Sys = %v MB\n", bToMB(m1.Sys))
	fmt.Printf("Total NumGC = %v\n", m1.NumGC)
	fmt.Printf("Delta TotalAlloc = %v MB\n", bToMB(m1.TotalAlloc-m0.TotalAlloc))
	fmt.Printf("Delta Sys = %v MB\n", bToMB(m1.Sys-m0.Sys))
	fmt.Printf("Delta NumGC = %v\n", m1.NumGC-m0.NumGC)
}

func normalizeImage(img *image.RGBA) {
	bounds := img.Bounds()
	var minVal, maxVal float64 = 255, 0

	// 首先找到最小和最大值
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.RGBAAt(x, y)
			minVal = math.Min(minVal, math.Min(float64(c.R), math.Min(float64(c.G), float64(c.B))))
			maxVal = math.Max(maxVal, math.Max(float64(c.R), math.Max(float64(c.G), float64(c.B))))
		}
	}

	// 然后进行归一化
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.RGBAAt(x, y)
			r := uint8((float64(c.R) - minVal) / (maxVal - minVal) * 255)
			g := uint8((float64(c.G) - minVal) / (maxVal - minVal) * 255)
			b := uint8((float64(c.B) - minVal) / (maxVal - minVal) * 255)
			img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
}

func convertToGray(img image.Image) *image.Gray {
	bounds := img.Bounds()
	grayImg := image.NewGray(bounds)

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			grayImg.Set(x, y, img.At(x, y))
		}
	}

	return grayImg
}

func compareImages(img1, img2 *image.Gray) bool {
	if img1.Bounds() != img2.Bounds() {
		return false
	}

	for y := img1.Bounds().Min.Y; y < img1.Bounds().Max.Y; y++ {
		for x := img1.Bounds().Min.X; x < img1.Bounds().Max.X; x++ {
			if math.Abs(float64(img1.GrayAt(x, y).Y)-float64(img2.GrayAt(x, y).Y)) > 5 {
				return false
			}
		}
	}

	return true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func bToMB(b uint64) uint64 {
	return b / 1024 / 1024
}

func logMemoryUsage(context string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("%s - Alloc = %v MiB", context, bToMB(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMB(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMB(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
