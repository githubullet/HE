package main

import (
	"crypto/rand"
	"fmt"
	"hash/fnv"
	"image"
	"image/color"
	"log"
	"os"
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

// func getCKKSParams(literal ckks.ParametersLiteral) (ckks.Parameters, error) {
// 	if cachedParams, ok := paramsCache.Load(literal); ok {
// 		return cachedParams.(ckks.Parameters), nil
// 	}
// 	params, err := ckks.NewParametersFromLiteral(literal)
// 	if err != nil {
// 		return ckks.Parameters{}, err
// 	}
// 	paramsCache.Store(literal, params)
// 	return params, nil
// }

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

// func getKeyPair(params ckks.Parameters) (*rlwe.SecretKey, *rlwe.PublicKey) {
// 	hashable := HashableParameters{params}
// 	if cachedKeyPair, ok := keyPairCache.Load(hashable.Hash()); ok {
// 		keyPair := cachedKeyPair.([2]interface{})
// 		return keyPair[0].(*rlwe.SecretKey), keyPair[1].(*rlwe.PublicKey)
// 	}
// 	kgen := ckks.NewKeyGenerator(params)
// 	sk, pk := kgen.GenKeyPair()
// 	keyPairCache.Store(hashable.Hash(), [2]interface{}{sk, pk})
// 	return sk, pk
// }

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

var plaintextPool = sync.Pool{
	New: func() interface{} {
		return ckks.NewPlaintext(params, params.MaxLevel())
	},
}

func init() {
	var err error
	params, err = getCKKSParams(ckks.PN14QP438)
	if err != nil {
		log.Fatal(err)
	}
	encoder = ckks.NewEncoder(params)
	sk, pk := getKeyPair(params)
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
			img.Set(startX+x, startY+y, color.RGBA{
				R: uint8(arr[y][x*3]),
				G: uint8(arr[y][x*3+1]),
				B: uint8(arr[y][x*3+2]),
				A: 255,
			})
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
	return real(res[0])
}

func main() {
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
	img, err := bmpRead("kingfisher.bmp")
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
	prngWrapper, err := NewPRNGWrapper(seed, 10000) // 设置一个合理的限制
	if err != nil {
		log.Fatal(err)
	}

	start = time.Now().UnixMicro()
	params, err = getCKKSParams(ckks.PN14QP438)
	check(err)
	encoder := ckks.NewEncoder(params)
	sk, pk := getKeyPair(params)
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	end = time.Now().UnixMicro()
	logMemoryUsage("After Setup")
	fmt.Printf("Setup       : %8d μs\n", end-start)

	height := img.Bounds().Max.Y
	width := img.Bounds().Max.X

	// Define the block size
	blockSize := 16

	// Create a new RGBA image to store the processed image
	processedImg := image.NewRGBA(image.Rect(0, 0, width, height))

	parray := make([][][][]float64, (height+blockSize-1)/blockSize)
	for i := range parray {
		parray[i] = make([][][]float64, (width+blockSize-1)/blockSize)
	}

	encStart := time.Now().UnixMicro()
	for startY := 0; startY < height; startY += blockSize {
		for startX := 0; startX < width; startX += blockSize {
			blockHeight := min(blockSize, height-startY)
			blockWidth := min(blockSize, width-startX)

			parray[startY/blockSize][startX/blockSize] = pixelToArray(
				img, startX, startY, blockWidth, blockHeight,
			)
			logMemoryUsage("After Converting Pixel to Array")

			encryptedPixels := make([][]*rlwe.Ciphertext, blockHeight)
			ciphertext := ckks.NewCiphertext(params, 1, params.MaxLevel())
			for i := 0; i < blockHeight; i++ {
				encryptedPixels[i] = make([]*rlwe.Ciphertext, blockWidth*3)
				for j := 0; j < blockWidth*3; j++ {
					encryptPixel(
						ciphertext, params, encoder, encryptor,
						prngWrapper, parray[startY/blockSize][startX/blockSize][i][j],
					)
					encryptedPixels[i][j] = ciphertext.CopyNew()
				}
			}
			logMemoryUsage("After Encryption")

			decbody := make([][][]float64, blockHeight)
			for i := 0; i < blockHeight; i++ {
				decbody[i] = make([][]float64, blockWidth)
				for j := 0; j < blockWidth; j++ {
					decbody[i][j] = make([]float64, 3)
					for k := 0; k < 3; k++ {
						decbody[i][j][k] = decryptPixel(
							encryptedPixels[i][j*3+k], params, encoder, decryptor, prngWrapper,
						)
					}
				}
			}
			logMemoryUsage("After Decryption")

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
			logMemoryUsage("After Decoding")
		}
	}
	encEnd := time.Now().UnixMicro()
	fmt.Printf("Encryption  : %8d μs\n", encEnd-encStart)

	decStart := time.Now().UnixMicro()
	for startY := 0; startY < height; startY += blockSize {
		for startX := 0; startX < width; startX += blockSize {
			blockHeight := min(blockSize, height-startY)
			blockWidth := min(blockSize, width-startX)

			encryptedPixels := make([][]*rlwe.Ciphertext, blockHeight)
			ciphertext := ckks.NewCiphertext(params, 1, params.MaxLevel())
			for i := 0; i < blockHeight; i++ {
				encryptedPixels[i] = make([]*rlwe.Ciphertext, blockWidth*3)
				for j := 0; j < blockWidth*3; j++ {
					encryptPixel(
						ciphertext, params, encoder, encryptor,
						prngWrapper, parray[startY/blockSize][startX/blockSize][i][j],
					)
					encryptedPixels[i][j] = ciphertext.CopyNew()
				}
			}

			decbody := make([][][]float64, blockHeight)
			for i := 0; i < blockHeight; i++ {
				decbody[i] = make([][]float64, blockWidth)
				for j := 0; j < blockWidth; j++ {
					decbody[i][j] = make([]float64, 3)
					for k := 0; k < 3; k++ {
						decbody[i][j][k] = decryptPixel(
							encryptedPixels[i][j*3+k], params, encoder, decryptor, prngWrapper,
						)
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

	if err := bmpWrite("kingfisher2.bmp", processedImg); err != nil {
		log.Fatal("Failed to write image:", err)
	}
	if err := bmpWrite("kingfisher3.bmp", img); err != nil {
		log.Fatal("Failed to write image:", err)
	}

	afterPixel1 := convertToGray(processedImg)
	afterPixel2 := convertToGray(img)

	if compareImages(afterPixel1, afterPixel2) {
		fmt.Println("kingfisher2.bmp 和 kingfisher3.bmp similar")
	} else {
		fmt.Println("kingfisher2.bmp 和 kingfisher3.bmp not similar")
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

	for i := 0; i < img1.Bounds().Max.Y; i++ {
		for j := 0; j < img1.Bounds().Max.X; j++ {
			if abs(int(img1.GrayAt(j, i).Y)-int(img2.GrayAt(j, i).Y)) > 1 {
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
