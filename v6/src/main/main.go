package main

import (
	"crypto/rand"
	"encoding/binary"
	_ "encoding/binary"
	"encoding/gob"
	"fmt"
	"hash/fnv"
	"image"
	"image/color"
	"log"
	"os"
	"path/filepath"
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
			img.Set(startX+x, startY+y, color.RGBA{
				R: uint8(arr[y][x*3]),
				G: uint8(arr[y][x*3+1]),
				B: uint8(arr[y][x*3+2]),
				A: 255,
			})
		}
	}
}
func encryptRGBList(params ckks.Parameters, secretKey rlwe.SecretKey) ([]*rlwe.Ciphertext, []*rlwe.Ciphertext) {
	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, secretKey)
	// The list that needs to be encrypted
	//plainList := []float64{1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 0.0}
	var plainList []float64
	for i := 0; i <= 255; i++ {
		plainList = append(plainList, float64(i))
	}
	var zeroList []float64
	for i := 0; i < 10000; i++ {
		zeroList = append(zeroList, 0.0)
	}

	ciphertextList := make([]*rlwe.Ciphertext, len(plainList))
	for i, plain := range plainList {
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())
		// Wrap the single float64 value in a slice of float64
		encoder.Encode([]float64{plain}, plaintext, params.LogSlots())
		ciphertext := encryptor.EncryptNew(plaintext)
		ciphertextList[i] = ciphertext
	}

	cipherzeroList := make([]*rlwe.Ciphertext, len(zeroList))
	for i, zero := range zeroList {
		plaintext1 := ckks.NewPlaintext(params, params.MaxLevel())
		// Wrap the single float64 value in a slice of float64
		encoder.Encode([]float64{zero}, plaintext1, params.LogSlots())
		ciphertext1 := encryptor.EncryptNew(plaintext1)
		cipherzeroList[i] = ciphertext1
	}

	return ciphertextList, cipherzeroList
}

func AddEnc(params ckks.Parameters, ciphertextList []*rlwe.Ciphertext, cipherzeroList []*rlwe.Ciphertext, publicKey rlwe.PublicKey, rKey *rlwe.RelinearizationKey, pixelValue float64) *rlwe.Ciphertext {

	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rKey})
	//rando := rand.Intn(9999)
	var num uint32
	err := binary.Read(rand.Reader, binary.LittleEndian, &num)
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	rando := num % 9999
	enc := evaluator.AddNew(ciphertextList[int(pixelValue)], cipherzeroList[rando])

	return enc
}

/*
func encryptPixel(ciphertext *rlwe.Ciphertext, params ckks.Parameters,
	encoder ckks.Encoder, encryptor rlwe.Encryptor, prngWrapper *PRNGWrapper,
	pixelValue float64) {
	plaintext := plaintextPool.Get().(*rlwe.Plaintext)
	encoder.Encode([]float64{pixelValue}, plaintext, params.LogSlots())
	encryptor.Encrypt(plaintext, ciphertext)
	plaintextPool.Put(plaintext)
}

*/

var plaintextPool = sync.Pool{
	New: func() interface{} {
		return ckks.NewPlaintext(params, params.MaxLevel())
	},
}

func decryptPixel(ciphertext *rlwe.Ciphertext, params ckks.Parameters,
	encoder ckks.Encoder, decryptor rlwe.Decryptor, prngWrapper *PRNGWrapper) float64 {
	plaintext := plaintextPool.Get().(*rlwe.Plaintext)
	decryptor.Decrypt(ciphertext, plaintext)
	res := encoder.Decode(plaintext, params.LogSlots())
	plaintextPool.Put(plaintext)
	return real(res[0])
	//plaintext := new(rlwe.Plaintext) // 创建一个新的Plaintext实例
	//decryptor.Decrypt(ciphertext, plaintext)
	//res := encoder.Decode(plaintext, params.LogSlots())
	//return real(res[0])

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

func main() {
	// 设置图片和密文文件保存的路径
	imageFilePath := "/Users/sueyang/Desktop/Code/Single_key_CKKS/v4/src/main/lena100x100.bmp"
	encryptedFilesDir := "/Users/sueyang/Desktop/Code"
	os.MkdirAll(encryptedFilesDir, os.ModePerm)

	// 加密图片并保存密文
	encryptImageAndSaveCiphertext(imageFilePath, encryptedFilesDir)

	// 从密文文件解密并生成图片
	decryptCiphertextAndGenerateImage(imageFilePath, encryptedFilesDir)
}

func encryptImageAndSaveCiphertext(imageFilePath, encryptedFilesDir string) {
	start := time.Now().UnixMicro()
	img, err := bmpRead(imageFilePath)
	if err != nil {
		log.Fatal("Failed to read image:", err)
	}
	end := time.Now().UnixMicro()
	fmt.Printf("ScanPic     : %8d μs\n", end-start)
	fmt.Printf("Resolution : %4d x%4d\n", img.Bounds().Max.X, img.Bounds().Max.Y)

	// 创建 PRNGWrapper
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		log.Fatalf("failed to generate seed: %v", err)
	}
	// prngWrapper, err := NewPRNGWrapper(seed, 10000) // 设置一个合理的限制
	//prngWrapper, err := NewPRNGWrapper(seed, 100000000)
	//if err != nil {
	//	log.Fatal(err)
	//}

	start = time.Now().UnixMicro()
	params, err = getCKKSParams(ckks.PN12QP109)
	check(err)
	sk, pk := getKeyPair(params)
	rKey := ckks.NewKeyGenerator(params).GenRelinearizationKey(sk, 1)
	end = time.Now().UnixMicro()
	fmt.Printf("Setup       : %8d μs\n", end-start)

	start = time.Now().UnixMicro()
	ciphertextList, cipherzeroList := encryptRGBList(params, *sk)
	end = time.Now().UnixMicro()
	fmt.Printf("cache	: %8d μs\n", end-start)

	height := img.Bounds().Max.Y
	width := img.Bounds().Max.X

	// Define the block size
	blockSize := 64
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

			encryptedPixels := make([][]*rlwe.Ciphertext, blockHeight)
			//ciphertext := ckks.NewCiphertext(params, 1, params.MaxLevel())
			for i := 0; i < blockHeight; i++ {
				encryptedPixels[i] = make([]*rlwe.Ciphertext, blockWidth*3)
				for j := 0; j < blockWidth*3; j++ {
					encryptedPixels[i][j] = AddEnc(params, ciphertextList, cipherzeroList, *pk, rKey, parray[i][j])
				}
			}

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
	fmt.Printf("Encryption  : %8.6f s\n", float64(encEnd-encStart)/1e6)
}

func decryptCiphertextAndGenerateImage(imageFilePath, encryptedFilesDir string) {

	// 创建 PRNGWrapper
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		log.Fatalf("failed to generate seed: %v", err)
	}
	prngWrapper, err := NewPRNGWrapper(seed, 100000000)
	if err != nil {
		log.Fatal(err)
	}

	//start := time.Now().UnixMicro()
	params, err := getCKKSParams(ckks.PN12QP109)
	check(err)
	encoder := ckks.NewEncoder(params)

	sk, _ := getKeyPair(params)
	decryptor := ckks.NewDecryptor(params, sk)
	//end := time.Now().UnixMicro()
	//fmt.Printf("Setup       : %8d μs\n", end-start)

	// Read the original image to get its dimensions
	img, err := bmpRead(imageFilePath)
	if err != nil {
		log.Fatal("Failed to read image:", err)
	}
	height := img.Bounds().Max.Y
	width := img.Bounds().Max.X

	// Define the block size
	blockSize := 64
	// Create a new RGBA image to store the processed image
	processedImg := image.NewRGBA(image.Rect(0, 0, width, height))

	decStart := time.Now().UnixMicro()
	for startY := 0; startY < height; startY += blockSize {
		for startX := 0; startX < width; startX += blockSize {
			blockHeight := min(blockSize, height-startY)
			blockWidth := min(blockSize, width-startX)

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
	fmt.Printf("Decryption  : %8.6f s\n", float64(decEnd-decStart)/1e6)

	if err := bmpWrite("kingfisher2.bmp", processedImg); err != nil {
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
			if abs(int(img1.GrayAt(j, i).Y)-int(img2.GrayAt(j, i).Y)) > 2 {
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
