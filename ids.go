package main

import (
	"bytes"      //Save etmeden once buffera al aes encript yap oyle yaz
	"crypto/aes" //AES kutuphanesi
	"crypto/cipher"
	"crypto/hmac" //Hmac support
	"crypto/rand"
	"crypto/sha256" //Sifreleme icin
	"encoding/gob"  //Serialization icin simple binary protocol
	"encoding/hex"  //hex Cevirme icin
	"errors"
	"fmt"       //Standart kütüphane
	"io"        //Dosya islemleri
	"io/ioutil" //Readfile icin
	"log"
	"os"            //OS islemleri icin
	"os/user"       //Username almak icin
	"path/filepath" //Dir scan icin
	"runtime"       //OS tespiti icin
	"sort"
	"strconv"
	"strings" //String comparison icin
	"time"    //Sleep icin
)

func sys_enum() {

	if runtime.GOOS == "windows" { //Windows ise Windows klasorune yazabiliyo mu
		fmt.Println("You are running on Windows")

		w, uacerr := os.Create("C:\\Windows\\uactest.txt")
		if uacerr != nil {
			fmt.Println("***********************************\nYou may not have admin privilages!\n***********************************")
			panic(uacerr)
		}
		defer w.Close()

	} else if runtime.GOOS == "linux" { //Linux ise uid 0 mı
		fmt.Println("You are running on Linux") //Linux

		user, err := user.Current()
		if err != nil {
			panic(err)
		}
		//fmt.Println("Hi " + user.Name + " (id: " + user.Uid + ")")
		if user.Uid != "0" {
			fmt.Println("***********************************\nYou may not have admin privilages!\n***********************************")
		}

	} else {
		fmt.Println("Your OS does not supported!") //Linux
	}

}

func getsha256hash(file string) string {

	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("File reading error: ", err)
		return "delete"
	}

	h := hmac.New(sha256.New, []byte(hmac_key)) // Create a new HMAC by defining the hash type and the key (as byte array)
	h.Write([]byte(data))                       // Write Data to it
	sha := hex.EncodeToString(h.Sum(nil))       // Get result and encode as hexadecimal string
	return sha
}

func scanfiles(filehashmap map[string]string) int {

	filecount := 0
	root := ""

	if runtime.GOOS == "windows" {
		root = "C:\\" // c:\\
	} else {
		root = "/etc" // c:\\
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {

		if info.IsDir() {
			return nil
		}

		if runtime.GOOS == "windows" { //Windows ise sadece ini dosyalarini kontrol et
			if filepath.Ext(path) != ".ini" {
				return nil
			}
		} else {
			if filepath.Ext(path) != ".conf" { //Linux ise conf dosyalarına bak
				return nil
			}
		}

		filehashmap[path] = getsha256hash(path) //Hash map i doldur
		filecount++
		if (filecount % 10) == 0 {
			fmt.Print(".")
		}

		return nil
	})

	if err != nil {
		panic(err)
	}

	fmt.Println(".") //Fonskiyon bitisi yeni satir
	return filecount

}

func save(filehashmap map[string]string) {

	//------DB HASH CALCULATION------
	delete(filehashmap, "self")

	keys := make([]string, 0, len(filehashmap)) //MAP SIRALA
	for k := range filehashmap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var str1 string
	for _, k := range keys {
		if strings.Compare(k, "self") != 0 {
			str1 += filehashmap[k]
		}
	}

	h := hmac.New(sha256.New, []byte(hmac_key)) // Create a new HMAC by defining the hash type and the key (as byte array)
	h.Write([]byte(str1))                       // Write Data to it
	sha := hex.EncodeToString(h.Sum(nil))       // Get result and encode as hexadecimal string

	filehashmap["self"] = sha
	//---------------------------

	cache_bytes := new(bytes.Buffer)           // Bos buffer ac
	dataEncoder := gob.NewEncoder(cache_bytes) // serializer olustur
	dataEncoder.Encode(filehashmap)            // Serialize the data

	readBuf, _ := ioutil.ReadAll(cache_bytes)       // cannot use buffer (type *bytes.Buffer) as type []byte in argument to w.Write covertion
	sifrelibuf, enc_err := encrypt(aeskey, readBuf) // Aes ile sifrele

	if enc_err != nil {
		log.Fatal(enc_err)
	}

	file, opn_err := os.OpenFile(dbname, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if opn_err != nil {
		log.Fatal(opn_err)
	}
	//defer file.Close()    //Dosya kapatilmiyor ki baska biri program calisirken oynama yapamasin

	_, wrt_err := file.Write(sifrelibuf) //Byte lari dosyaya yaz
	if wrt_err != nil {
		log.Fatal(wrt_err)
	}

}

func recover(filehashmap map[string]string) {

	enc_bin_data, err := ioutil.ReadFile(dbname) // b has type []byte
	if err != nil {
		log.Fatal(err)
	}

	cozulmusbuf, dec_err := decrypt(aeskey, enc_bin_data) // Aes ile sifrele

	if dec_err != nil {
		log.Fatal(dec_err)
	}

	b := bytes.NewBuffer(cozulmusbuf)

	dataDecoder := gob.NewDecoder(b)
	decser_err := dataDecoder.Decode(&filehashmap)

	if decser_err != nil { //Eğer dosyada değişiklik olursa decode edemiyceh tata vericek
		log.Println("Database Corrupt!")
		log.Fatal(decser_err)
	}

	//------DB HASH VERIFICATION------
	save_hash := filehashmap["self"] //ESKI
	delete(filehashmap, "self")

	keys := make([]string, 0, len(filehashmap)) //MAP SIRALA
	for k := range filehashmap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var str1 string
	for _, k := range keys {
		str1 += filehashmap[k]
	}

	h := hmac.New(sha256.New, []byte(hmac_key)) // Create a new HMAC by defining the hash type and the key (as byte array)
	h.Write([]byte(str1))                       // Write Data to it
	sha := hex.EncodeToString(h.Sum(nil))       // Get result and encode as hexadecimal string

	if strings.Compare(save_hash, sha) != 0 {
		log.Fatal("DB Checksum Error!")
	}
	//---------------------------

}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)

	return text, nil
}

var dbname = "files.db"

var aeskey []byte   //Global key degiskeni yarat
var hmac_key []byte //Global key degiskeni yarat

func main() {

	hex_xor_aes_key := "76606670776c717c75776a6f606671646076606b66776c75716c6a6b6e607c24" //DB Encription key HEX and XOR ed with 5 (securityprojectaesencriptionkey!)
	hex_xor_hmac_key := "66766031363c6d6864667660667760716e607c"

	aeskey, _ = hex.DecodeString(hex_xor_aes_key) //Init AES Key
	for i, b := range aeskey {
		aeskey[i] = b ^ 5 // xor with 5
	}

	hmac_key, _ = hex.DecodeString(hex_xor_hmac_key) //Init HMAC Key
	for i, b := range hmac_key {
		hmac_key[i] = b ^ 5 // xor with 5
	}

	sys_enum()

	filehashmap := make(map[string]string)

	if _, err := os.Stat(dbname); os.IsNotExist(err) { //Dosyayı okumaya çalış

		fmt.Println("DB File Can Not Be Found.")
		fmt.Println("Configuration Files Scanning..")
		scanfiles(filehashmap)

		fmt.Println(strconv.Itoa(len(filehashmap)) + " files watching.")
		save(filehashmap) //İlk çalıştırmadan sonra save al

	} else {

		recover(filehashmap)
		//fmt.Println(filehashmap) //Print recover file to debug
		fmt.Println("DB File Found and recovered")
		fmt.Println(strconv.Itoa(len(filehashmap)) + " files watching.")
		save(filehashmap) //Save etmeye normalde gerek yok ama sadece file lock etsin diye save aliyoruz
	}

	for { //Sonsuz dongu

		for k, v := range filehashmap { //Hashmapteki her file icin

			if strings.Compare(k, "self") == 0 { //DBChecksum'i atla
				continue
			}

			// fmt.Printf("key[%s] value[%s]\n", k, v)

			hash_of_file := getsha256hash(k)

			if strings.Compare(hash_of_file, "delete") == 0 {
				delete(filehashmap, k)
				fmt.Print(time.Now().Format("2006-01-02 15:04:05 "))
				fmt.Print(k)
				fmt.Println(" Deleted!")
				save(filehashmap) //Dosyaya da save et
			}

			if strings.Compare(hash_of_file, v) == 0 { //Yeni hash ile hashmapteki hash ayniysa
				_ = v // v is now "used"
			} else {
				fmt.Print(time.Now().Format("2006-01-02 15:04:05 "))
				fmt.Print(k)
				fmt.Println(" Changed!")
				filehashmap[k] = hash_of_file
				save(filehashmap) //Dosyaya da save et
			}
		}

		time.Sleep(1000 * time.Millisecond) //500ms uyu

	}

}
