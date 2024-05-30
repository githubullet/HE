package main

import (
	"fmt"
	"image"
	"image/color"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	_ "golang.org/x/image/bmp"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/image/bmp"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func bmpRead(filename string) image.Image {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		log.Fatal(err)
	}

	return img
}

func bmpWrite(filename string, img image.Image) {
	outFile, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	err = bmp.Encode(outFile, img)
	if err != nil {
		log.Fatal(err)
	}
}

func pixelToArray(img image.Image) [][]float64 {
	bounds := img.Bounds()
	width, height := bounds.Max.X, bounds.Max.Y

	ret := make([][]float64, height)
	for y := 0; y < height; y++ {
		ret[y] = make([]float64, width*3)
		for x := 0; x < width; x++ {
			c := color.GrayModel.Convert(img.At(x, y))
			gray, _, _, _ := c.RGBA()
			ret[y][x*3+0] = float64(gray >> 8)
			ret[y][x*3+1] = float64(gray >> 8)
			ret[y][x*3+2] = float64(gray >> 8)
		}
	}
	return ret
}

func arrayToImage(arr [][]float64) *image.Gray {
	height := len(arr)
	width := len(arr[0]) / 3

	img := image.NewGray(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.Gray{uint8(arr[y][x*3])})
		}
	}
	return img
}

// func encryptPixel(ciphertext *rlwe.Ciphertext, params ckks.Parameters, encoder ckks.Encoder, encryptor *rlwe.Encryptor, pixelValue float64) {
// 	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
// 	encoder.Encode([]float64{pixelValue}, plaintext, params.LogSlots())
// 	encryptor.Encrypt(plaintext, ciphertext)
// }

// func decryptPixel(ciphertext *rlwe.Ciphertext, params ckks.Parameters, encoder ckks.Encoder, decryptor *rlwe.Decryptor) float64 {
// 	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
// 	decryptor.Decrypt(ciphertext, plaintext)
// 	res := encoder.Decode(plaintext, params.LogSlots())
// 	return real(res[0])
// }

func encryptPixel(ciphertext *rlwe.Ciphertext, params ckks.Parameters, encoder ckks.Encoder, encryptor rlwe.Encryptor, pixelValue float64) {
	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode([]float64{pixelValue}, plaintext, params.LogSlots())
	encryptor.Encrypt(plaintext, ciphertext)
}

func decryptPixel(ciphertext *rlwe.Ciphertext, params ckks.Parameters, encoder ckks.Encoder, decryptor rlwe.Decryptor) float64 {
	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	decryptor.Decrypt(ciphertext, plaintext)
	res := encoder.Decode(plaintext, params.LogSlots())
	return real(res[0])
}

func main() {

	start := time.Now().UnixMicro()
	img := bmpRead("kingfisher.bmp")
	end := time.Now().UnixMicro()
	fmt.Printf("ScanPic     : %8d μs\n", end-start)
	fmt.Printf("Resolution : %4d x%4d\n", img.Bounds().Max.X, img.Bounds().Max.Y)

	start = time.Now().UnixMicro()
	params, err := ckks.NewParametersFromLiteral(ckks.PN14QP438)
	check(err)
	encoder := ckks.NewEncoder(params)
	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	end = time.Now().UnixMicro()

	fmt.Printf("Setup       : %8d μs\n", end-start)

	parray := pixelToArray(img)
	height := len(parray)
	width := len(parray[0]) / 3

	encStart := time.Now().UnixMicro()
	encryptedPixels := make([][]*rlwe.Ciphertext, height)
	ciphertext := ckks.NewCiphertext(params, 1, params.MaxLevel())
	for i := 0; i < height; i++ {
		encryptedPixels[i] = make([]*rlwe.Ciphertext, width*3)
		for j := 0; j < width*3; j++ {
			encryptPixel(ciphertext, params, encoder, encryptor, parray[i][j])
			encryptedPixels[i][j] = ciphertext.CopyNew()
		}
	}
	encEnd := time.Now().UnixMicro()
	fmt.Printf("Encryption  : %8.6f s\n", float64(encEnd-encStart)/1e6)

	decStart := time.Now().UnixMicro()
	decbody := make([][][]float64, height)
	for i := 0; i < height; i++ {
		decbody[i] = make([][]float64, width)
		for j := 0; j < width; j++ {
			decbody[i][j] = make([]float64, 3)
			for k := 0; k < 3; k++ {
				decbody[i][j][k] = decryptPixel(encryptedPixels[i][j*3+k], params, encoder, decryptor)
			}
		}
	}
	decEnd := time.Now().UnixMicro()
	fmt.Printf("Decryption  : %8.6f s\n", float64(decEnd-decStart)/1e6)

	// 将三维数组转换为二维数组
	decbody2d := make([][]float64, height)
	for i := 0; i < height; i++ {
		decbody2d[i] = make([]float64, width*3)
		for j := 0; j < width; j++ {
			for k := 0; k < 3; k++ {
				decbody2d[i][j*3+k] = decbody[i][j][k]
			}
		}
	}

	decodeStart := time.Now().UnixMicro()
	afterImage := arrayToImage(decbody2d)
	decodeEnd := time.Now().UnixMicro()
	fmt.Printf("Decoding    : %8d μs\n", decodeEnd-decodeStart)

	bmpWrite("kingfisher2.bmp", afterImage)
	bmpWrite("kingfisher3.bmp", img)

	afterPixel1 := convertToGray(bmpRead("kingfisher2.bmp"))
	afterPixel2 := convertToGray(bmpRead("kingfisher3.bmp"))

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

	// 获取内存使用情况的详细报告
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc = %v MB", bToMB(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MB", bToMB(m.TotalAlloc))
	fmt.Printf("\tSys = %v MB", bToMB(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
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
