package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib
	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

type PrivateKey = userlib.PrivateKey

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// SharingRecord to serialized/deserialize in the data store.
type SharingRecord struct {
	InodeAddr string
	FileKey   []byte
}

//User : User structure used to store the user information
type User struct {
	Username string
	Password string
	RSAKey   *PrivateKey
	FileMap  map[string]SharingRecord
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type DataHash struct {
	Data []byte
	Hash []byte
}

type Inode struct {
	NumBlocks int
	Singind   [32]string
	Doubind   [12]string
}

type msg struct {
	Mssg []byte
	Sign []byte
}

func Hash(value []byte) []byte {
	mac := userlib.NewSHA256()
	mac.Write(value)
	return mac.Sum(nil)
}

func HMAChash(key []byte, value []byte) []byte {
	mac := userlib.NewHMAC(key)
	mac.Write(value)
	return mac.Sum(nil)
}

func checkHMAC(key []byte, value []byte, hash []byte) bool {
	mac := userlib.NewHMAC(key)
	mac.Write(value)
	expectedMAC := mac.Sum(nil)
	return userlib.Equal(hash, expectedMAC)
}

func Encrypt(key []byte, value []byte) []byte {
	ciphertext := make([]byte, userlib.BlockSize+len(value))
	iv := ciphertext[:userlib.BlockSize]
	// Load random data
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(value))

	return ciphertext
}

func Decrypt(key []byte, value []byte) []byte {
	cipher := userlib.CFBDecrypter(key, value[:userlib.BlockSize])
	cipher.XORKeyStream(value[userlib.BlockSize:], value[userlib.BlockSize:])
	return value[userlib.BlockSize:]
}

func AddData(data_bytes []byte, addr string, key []byte) (err error) {
	data_hash := HMAChash(key, data_bytes)
	data_info := DataHash{Data: data_bytes, Hash: data_hash}
	info_bytes, err := json.Marshal(data_info)
	if err != nil {
		return err
	}
	enc_info := Encrypt(key, info_bytes)
	userlib.DatastoreSet(addr, enc_info)

	return err
}

func AddInode(data []byte, record SharingRecord, fnode Inode, Old int) (err error) {
	fnode.NumBlocks = Old + len(data)/configBlockSize
	if fnode.NumBlocks <= 32 {
		for i := Old; i < fnode.NumBlocks; i++ {
			fnode.Singind[i] = hex.EncodeToString(userlib.RandomBytes(32))
			// dataBytes, err := json.Marshal(data[(i-Old)*configBlockSize : (i+1-Old)*configBlockSize-1])
			// if err != nil {
			// fmt.Printf("eei %d\n", i)
			// return err
			// }
			//fmt.Printf("hi %d %d %s\n", (i-Old)*configBlockSize, (i+1-Old)*configBlockSize-1, hex.EncodeToString(data[0:1]))
			data_bytes := data[(i-Old)*(configBlockSize) : (i+1-Old)*(configBlockSize)]
			//fmt.Printf("hi %d\n", i)
			err = AddData(data_bytes, fnode.Singind[i], record.FileKey)
		}
		//fmt.Printf("done")
	} else {
		var count = Old
		if Old <= 32 {
			for i := Old; i < 32; i++ {
				count++
				fnode.Singind[i] = hex.EncodeToString(userlib.RandomBytes(32))
				data_bytes := data[(i-Old)*configBlockSize : (i+1-Old)*configBlockSize]
				err = AddData(data_bytes, fnode.Singind[i], record.FileKey)
			}
			// fmt.Printf("dds\n")
			var flag = 0
			for j := 0; j < 12; j++ {
				fnode.Doubind[j] = hex.EncodeToString(userlib.RandomBytes(32))
				var Singind [64]string
				for k := 0; k < 64; k++ {
					count++
					if count > fnode.NumBlocks {
						flag = 1
						break
					}
					Singind[k] = hex.EncodeToString(userlib.RandomBytes(32))
					data_bytes := data[(32-Old+j*64+k)*configBlockSize : (33-Old+j*64+k)*configBlockSize]
					err = AddData(data_bytes, Singind[k], record.FileKey)
				}
				Singind_bytes, err := json.Marshal(Singind)
				if err != nil {
					return err
				}
				err = AddData(Singind_bytes, fnode.Doubind[j], record.FileKey)
				if flag == 1 {
					break
				}
			}
		} else {
			var j_old int
			var k_old int
			j_old = (Old - 32) / 64
			k_old = (Old - 32) - (j_old * 64)
			if k_old != 0 {
				enc_info, ok := userlib.DatastoreGet(fnode.Doubind[j_old])
				if enc_info == nil || ok == false {
					return errors.New("Data corrupted")
				}
				info_bytes := Decrypt(record.FileKey, enc_info)
				var Singind_info DataHash
				err := json.Unmarshal(info_bytes, &Singind_info)
				if err != nil {
					return err
				}
				if checkHMAC(record.FileKey, Singind_info.Data, Singind_info.Hash) == false {
					return errors.New("Data corrupted")
				}
				var Singind [64]string
				err = json.Unmarshal(Singind_info.Data, &Singind)
				if err != nil {
					return err
				}
				for k := k_old; k < 64; k++ {
					count++
					if count > fnode.NumBlocks {
						break
					}
					Singind[k] = hex.EncodeToString(userlib.RandomBytes(32))
					data_bytes := data[(32+j_old*64+k-Old)*configBlockSize : (33+j_old*64+k-Old)*configBlockSize]
					err = AddData(data_bytes, Singind[k], record.FileKey)
				}
				Singind_bytes, err := json.Marshal(Singind)
				if err != nil {
					return err
				}
				err = AddData(Singind_bytes, fnode.Doubind[j_old], record.FileKey)
			}
			var flag = 0
			for j := j_old+1; j < 12; j++ {
				fnode.Doubind[j] = hex.EncodeToString(userlib.RandomBytes(32))
				var Singind [64]string
				for k := 0; k < 64; k++ {
					count++
					if count > fnode.NumBlocks {
						flag = 1
						break
					}
					Singind[k] = hex.EncodeToString(userlib.RandomBytes(32))
					data_bytes := data[(32-Old+j*64+k)*configBlockSize : (33-Old+j*64+k)*configBlockSize]
					err = AddData(data_bytes, Singind[k], record.FileKey)
				}
				Singind_bytes, err := json.Marshal(Singind)
				if err != nil {
					return err
				}
				err = AddData(Singind_bytes, fnode.Doubind[j], record.FileKey)
				if flag == 1 {
					break
				}
			}
		}
	}
	inode_bytes, err := json.Marshal(fnode)
	if err != nil {
		return err
	}
	err = AddData(inode_bytes, record.InodeAddr, record.FileKey)
	return err
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if(err != nil) {
		return err
	}
	filename_hash := hex.EncodeToString(Hash([]byte(filename)))
	var record SharingRecord
	var ok bool
	record, ok = userdata.FileMap[filename_hash]
	if ok == false {
		record.InodeAddr = hex.EncodeToString(userlib.RandomBytes(32))
		record.FileKey = userlib.RandomBytes(16)
		if userdata.FileMap == nil {
			userdata.FileMap = make(map[string]SharingRecord)
			//fmt.Printf("roughhhh")
		}
		userdata.FileMap[filename_hash] = record
		pkey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
		addr := hex.EncodeToString(Hash([]byte(userdata.Username + userdata.Password)))
		user_bytes, err := json.Marshal(userdata)
		if err != nil {
			return err
		}
		err = AddData(user_bytes, addr, pkey)
		if err != nil {
			return err
		}
	}
	var fnode Inode
	err = AddInode(data, record, fnode, 0)
	if err != nil {
		return err
	}
	return err
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if(err != nil) {
		return err
	}
	filename_hash := hex.EncodeToString(Hash([]byte(filename)))
	var record SharingRecord
	var ok bool
	record, ok = userdata.FileMap[filename_hash]
	if ok == false {
		return errors.New("File Not Found")
	}
	enc_info, ok := userlib.DatastoreGet(record.InodeAddr)
	if enc_info == nil || ok == false {
		return errors.New("No Inode found")
	}
	info_bytes := Decrypt(record.FileKey, enc_info)
	var inode_info DataHash
	err = json.Unmarshal(info_bytes, &inode_info)
	if err != nil {
		return err
	}
	if checkHMAC(record.FileKey, inode_info.Data, inode_info.Hash) == false {
		return errors.New("Data corrupted")
	}
	var fnode Inode
	err = json.Unmarshal(inode_info.Data, &fnode)
	if err != nil {
		return err
	}
	err = AddInode(data, record, fnode, fnode.NumBlocks)
	if err != nil {
		return err
	}
	return err
}

func CheckFileIntegrity(fnode Inode, record SharingRecord) (err error) {
	if fnode.NumBlocks < 32 {
		for i := 0; i < fnode.NumBlocks; i++ {
			enc_info, ok := userlib.DatastoreGet(fnode.Singind[i])
			if enc_info == nil || ok == false {
				return errors.New("No Data found at some address; NumBlocks<32")
			}
			info_bytes := Decrypt(record.FileKey, enc_info)
			var data_info DataHash
			err := json.Unmarshal(info_bytes, &data_info)
			if err != nil {
				return err
			}
			if checkHMAC(record.FileKey, data_info.Data, data_info.Hash) == false {
				return errors.New("Data corrupted")
			}
		}
	} else {
		for i := 0; i < 32; i++ {
			enc_info, ok := userlib.DatastoreGet(fnode.Singind[i])
			if enc_info == nil || ok == false {
				return errors.New("No Data found at some address; i, NumBlocks>32")
			}
			info_bytes := Decrypt(record.FileKey, enc_info)
			var data_info DataHash
			err := json.Unmarshal(info_bytes, &data_info)
			if err != nil {
				return err
			}
			if checkHMAC(record.FileKey, data_info.Data, data_info.Hash) == false {
				return errors.New("Data corrupted")
			}
		}
		var j_old int
		var k_old int
		j_old = (fnode.NumBlocks - 32) / 64
		k_old = (fnode.NumBlocks - 32) - (j_old * 64)
		for j := 0; j < j_old; j++ {
			enc_info, ok := userlib.DatastoreGet(fnode.Doubind[j])
			if enc_info == nil || ok == false {
				return errors.New("No Data found at some address; j")
			}
			info_bytes := Decrypt(record.FileKey, enc_info)
			var Singind_info DataHash
			err := json.Unmarshal(info_bytes, &Singind_info)
			if err != nil {
				return err
			}
			if checkHMAC(record.FileKey, Singind_info.Data, Singind_info.Hash) == false {
				return errors.New("Data corrupted")
			}
			var Singind [64]string
			err = json.Unmarshal(Singind_info.Data, &Singind)
			if err != nil {
				return err
			}
			for k := 0; k < 64; k++ {
				enc_info, ok := userlib.DatastoreGet(Singind[k])
				if enc_info == nil || ok == false {
					return errors.New("No Data found at some address; j,k")
				}
				info_bytes := Decrypt(record.FileKey, enc_info)
				var data_info DataHash
				err := json.Unmarshal(info_bytes, &data_info)
				if err != nil {
					return err
				}
				if checkHMAC(record.FileKey, data_info.Data, data_info.Hash) == false {
					return errors.New("Data corrupted")
				}
			}
		}
		enc_info, ok := userlib.DatastoreGet(fnode.Doubind[j_old])
		if enc_info == nil || ok == false {
			return errors.New("No Data found at some address; j_old")
		}
		info_bytes := Decrypt(record.FileKey, enc_info)
		var Singind_info DataHash
		err := json.Unmarshal(info_bytes, &Singind_info)
		if err != nil {
			return err
		}
		if checkHMAC(record.FileKey, Singind_info.Data, Singind_info.Hash) == false {
			return errors.New("Data corrupted")
		}
		var Singind [64]string
		err = json.Unmarshal(Singind_info.Data, &Singind)
		if err != nil {
			return err
		}
		for k := 0; k < k_old; k++ {
			enc_info, ok := userlib.DatastoreGet(Singind[k])
			if enc_info == nil || ok == false {
				return errors.New("No Data found at some address; j_old,k")
			}
			info_bytes := Decrypt(record.FileKey, enc_info)
			var data_info DataHash
			err := json.Unmarshal(info_bytes, &data_info)
			if err != nil {
				return err
			}
			if checkHMAC(record.FileKey, data_info.Data, data_info.Hash) == false {
				return errors.New("Data corrupted")
			}
		}
	}
	return nil
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if(err != nil) {
		return nil, err
	}
	filename_hash := hex.EncodeToString(Hash([]byte(filename)))
	var record SharingRecord
	var ok bool
	record, ok = userdata.FileMap[filename_hash]
	if ok == false {
		return nil, errors.New("File Not Found")
	}
	enc_info, ok := userlib.DatastoreGet(record.InodeAddr)
	if enc_info == nil || ok == false {
		return nil, errors.New("No Inode found")
	}
	info_bytes := Decrypt(record.FileKey, enc_info)
	var inode_info DataHash
	err = json.Unmarshal(info_bytes, &inode_info)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("%s\n", hex.EncodeToString(inode_info.Data))
	if checkHMAC(record.FileKey, inode_info.Data, inode_info.Hash) == false {
		return nil, errors.New("Data corrupted")
	}
	var fnode Inode
	err = json.Unmarshal(inode_info.Data, &fnode)
	if err != nil {
		return nil, err
	}
	if offset >= fnode.NumBlocks {
		return nil, errors.New("No data at Offset")
	}
	err = CheckFileIntegrity(fnode, record)
	if err != nil {
		return nil, err
	}
	if offset < 32 {
		enc_info, ok := userlib.DatastoreGet(fnode.Singind[offset])
		if enc_info == nil || ok == false {
			return nil, errors.New("No Data found")
		}
		info_bytes := Decrypt(record.FileKey, enc_info)
		var data_info DataHash
		err := json.Unmarshal(info_bytes, &data_info)
		if err != nil {
			return nil, err
		}
		if checkHMAC(record.FileKey, data_info.Data, data_info.Hash) == false {
			return nil, errors.New("Data corrupted")
		}
		return data_info.Data, err
	} else {
		var j_old int
		var k_old int
		j_old = (offset - 32) / 64
		k_old = (offset - 32) - (j_old * 64)
		enc_info, ok := userlib.DatastoreGet(fnode.Doubind[j_old])
		if enc_info == nil || ok == false {
			return nil, errors.New("Data corrupted")
		}
		info_bytes := Decrypt(record.FileKey, enc_info)
		var Singind_info DataHash
		err := json.Unmarshal(info_bytes, &Singind_info)
		if err != nil {
			return nil, err
		}
		if checkHMAC(record.FileKey, Singind_info.Data, Singind_info.Hash) == false {
			return nil, errors.New("Data corrupted")
		}
		var Singind [64]string
		err = json.Unmarshal(Singind_info.Data, &Singind)
		if err != nil {
			return nil, err
		}
		enc_info, ok = userlib.DatastoreGet(Singind[k_old])
		if enc_info == nil || ok == false {
			return nil, errors.New("Data corrupted")
		}
		info_bytes = Decrypt(record.FileKey, enc_info)
		var data_info DataHash
		err = json.Unmarshal(info_bytes, &data_info)
		if err != nil {
			return nil, err
		}
		if checkHMAC(record.FileKey, data_info.Data, data_info.Hash) == false {
			return nil, errors.New("Data corrupted")
		}
		return data_info.Data, err
	}
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if(err != nil) {
		return "", err
	}
	recvPubKey, ok := userlib.KeystoreGet(recipient)
	if ok == false {
		return "", errors.New("Recipient's Public key not found")
	}

	filename_hash := hex.EncodeToString(Hash([]byte(filename)))
	var Record SharingRecord
	Record, ok = userdata.FileMap[filename_hash]
	if ok == false {
		return "nil", errors.New("File Not Found")
	}

	msgBytes, err := json.Marshal(Record)
	if err != nil {
		return "", err
	}
	signmssg, err := userlib.RSASign(userdata.RSAKey, msgBytes)
	if err != nil {
		return "", err
	}
	encymssg, err := userlib.RSAEncrypt(&recvPubKey, msgBytes, []byte("Tag"))
	if err != nil {
		return "", err
	}
	mssgsendc := msg{Mssg: encymssg, Sign: signmssg}
	MSSG, err := json.Marshal(mssgsendc)
	if err != nil {
		return "", err
	}

	sendmssg := hex.EncodeToString(MSSG)

	return sendmssg, err
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) (err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if(err != nil) {
		return err
	}
	mssgrecv, err := hex.DecodeString(msgid)
	if err != nil {
		return err
	}

	sendPubKey, ok := userlib.KeystoreGet(sender)
	if ok == false {
		return errors.New("Sender's Public key not found")
	}

	var message_r msg
	err = json.Unmarshal(mssgrecv, &message_r)
	if err != nil {
		return err
	}

	encymssg := message_r.Mssg
	msgBytes, err := userlib.RSADecrypt(userdata.RSAKey, encymssg, []byte("Tag"))
	if err != nil {
		return err
	}

	sign := message_r.Sign
	err = userlib.RSAVerify(&sendPubKey, msgBytes, sign)
	if err != nil {
		return err
	}

	var message SharingRecord
	err = json.Unmarshal(msgBytes, &message)
	if err != nil {
		return err
	}

	filename_hash := hex.EncodeToString(Hash([]byte(filename)))
	if userdata.FileMap == nil {
		userdata.FileMap = make(map[string]SharingRecord)
	}
	userdata.FileMap[filename_hash] = message
	pkey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	addr := hex.EncodeToString(Hash([]byte(userdata.Username + userdata.Password)))
	user_bytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	err = AddData(user_bytes, addr, pkey)
	if err != nil {
		return err
	}
	return err
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if(err != nil) {
		return err
	}
	filename_hash := hex.EncodeToString(Hash([]byte(filename)))
	var oldrecord SharingRecord
	var newrecord SharingRecord
	var ok bool
	oldrecord, ok = userdata.FileMap[filename_hash]
	if ok == false {
		return errors.New("File Not Found")
	}
	newrecord.InodeAddr = hex.EncodeToString(userlib.RandomBytes(32))
	newrecord.FileKey = userlib.RandomBytes(16)
	enc_info, ok := userlib.DatastoreGet(oldrecord.InodeAddr)
	if enc_info == nil || ok == false {
		return errors.New("No Inode found")
	}
	info_bytes := Decrypt(oldrecord.FileKey, enc_info)
	var inode_info DataHash
	err = json.Unmarshal(info_bytes, &inode_info)
	if err != nil {
		return err
	}
	var fnode Inode
	err = json.Unmarshal(inode_info.Data, &fnode)
	if err != nil {
		return err
	}
	var total_data []byte
	if fnode.NumBlocks <= 32 {
		for i := 0; i < fnode.NumBlocks; i++ {
			data, err := userdata.LoadFile(filename, i)
			if err != nil {
				return err
			}
			total_data = append(total_data, data...)
		}
	} else {
		for i := 0; i < 32; i++ {
			data, err := userdata.LoadFile(filename, i)
			if err != nil {
				return err
			}
			total_data = append(total_data, data...)
		}
		var j_old int
		var k_old int
		j_old = (fnode.NumBlocks - 32) / 64
		k_old = (fnode.NumBlocks - 32) - (j_old * 64)
		for j := 0; j < j_old; j++ {
			for k := 0; k < 64; k++ {
				data, err := userdata.LoadFile(filename, 32+j*64+k)
				if err != nil {
					return err
				}
				total_data = append(total_data, data...)
			}
		}
		for k := 0; k < k_old; k++ {
			data, err := userdata.LoadFile(filename, 32+j_old*64+k)
			if err != nil {
				return err
			}
			total_data = append(total_data, data...)
		}
	}
	if fnode.NumBlocks <= 32 {
		for i := 0; i < fnode.NumBlocks; i++ {
			userlib.DatastoreDelete(fnode.Singind[i])
		}
	} else {
		for i := 0; i < 32; i++ {
			userlib.DatastoreDelete(fnode.Singind[i])
		}
		var j_old int
		var k_old int
		j_old = (fnode.NumBlocks - 32) / 64
		k_old = (fnode.NumBlocks - 32) - (j_old * 64)
		for j := 0; j < j_old; j++ {
			enc_info, ok := userlib.DatastoreGet(fnode.Doubind[j])
			if enc_info == nil || ok == false {
				return errors.New("Data corrupted")
			}
			info_bytes := Decrypt(oldrecord.FileKey, enc_info)
			var Singind_info DataHash
			err := json.Unmarshal(info_bytes, &Singind_info)
			if err != nil {
				return err
			}
			var Singind [64]string
			err = json.Unmarshal(Singind_info.Data, &Singind)
			if err != nil {
				return err
			}
			for k := 0; k < 64; k++ {
				userlib.DatastoreDelete(Singind[k])
			}
			userlib.DatastoreDelete(fnode.Doubind[j])
		}
		if k_old != 0 {
			enc_info, ok := userlib.DatastoreGet(fnode.Doubind[j_old])
			if enc_info == nil || ok == false {
				return errors.New("Data corrupted")
			}
			info_bytes := Decrypt(oldrecord.FileKey, enc_info)
			var Singind_info DataHash
			err := json.Unmarshal(info_bytes, &Singind_info)
			if err != nil {
				return err
			}
			var Singind [64]string
			err = json.Unmarshal(Singind_info.Data, &Singind)
			if err != nil {
				return err
			}
			for k := 0; k < k_old; k++ {
				userlib.DatastoreDelete(Singind[k])
			}
			userlib.DatastoreDelete(fnode.Doubind[j_old])
		}
	}
	userlib.DatastoreDelete(oldrecord.InodeAddr)
	var fnode_new Inode
	err = AddInode(total_data, newrecord, fnode_new, 0)
	if err != nil {
		return err
	}
	if userdata.FileMap == nil {
		userdata.FileMap = make(map[string]SharingRecord)
	}
	userdata.FileMap[filename_hash] = newrecord
	pkey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	addr := hex.EncodeToString(Hash([]byte(userdata.Username + userdata.Password)))
	user_bytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	err = AddData(user_bytes, addr, pkey)
	if err != nil {
		return err
	}
	return err
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	pkey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	rsakey, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet(username, rsakey.PublicKey)
	user := User{Username: username, Password: password, RSAKey: rsakey}
	addr := hex.EncodeToString(Hash([]byte(username + password)))
	user_bytes, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	err = AddData(user_bytes, addr, pkey)

	return &user, err
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	pkey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	addr := hex.EncodeToString(Hash([]byte(username + password)))
	enc_info, ok := userlib.DatastoreGet(addr)
	if enc_info == nil || ok == false {
		return nil, errors.New("No User data found")
	}
	info_bytes := Decrypt(pkey, enc_info)
	var user_info DataHash
	err = json.Unmarshal(info_bytes, &user_info)
	if err != nil {
		return nil, err
	}
	if checkHMAC(pkey, user_info.Data, user_info.Hash) == false {
		return nil, errors.New("Invalid input data / Data corrupted")
	}
	var user User
	err = json.Unmarshal(user_info.Data, &user)
	if err != nil {
		return nil, err
	}

	return &user, err
}