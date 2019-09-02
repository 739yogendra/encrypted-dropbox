package assn1

import "github.com/sarkarbidya/CS628-assn1/userlib"
import "testing"
import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.


func TestInitUser(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	userlib.DebugPrint = false
	user, err1 := InitUser("alice", "fubar")
	if err1 != nil {
		t.Log("Failed to initialize user")

	} else {
		t.Log("Initialized valid user", user)
	}

	// add more test cases here
	setBlockSize(64)
}

func TestUserStorage(t *testing.T) {
	u1, err1 := GetUser("alice", "fubar")
	if err1 != nil {
		t.Log("Cannot load data for invalid user", u1)
	} else {
		t.Log("Data loaded for valid user", u1)
		data := userlib.RandomBytes(64)
		u1.StoreFile("file1", data)
		data2, err2 := u1.LoadFile("file1",0)
		if err2 != nil {
			t.Error("Failed to load file", err2)
		}
		if !reflect.DeepEqual(data, data2) {
			t.Error("Downloaded file is not the same", len(data), "\n", len(data2))
		}
	}

	u1, err1 = GetUser("alice", "foobar")
	if err1 != nil {
		t.Log("Cannot load data for invalid user", u1)
	} else {
		t.Log("Data loaded for valid user", u1)
		data := userlib.RandomBytes(64)
		u1.StoreFile("file1", data)
		data2, err2 := u1.LoadFile("file1",0)
		if err2 != nil {
			t.Error("Failed to load file", err2)
		}
		if !reflect.DeepEqual(data, data2) {
			t.Error("Downloaded file is not the same", data, data2)
		}
	}

	// add more test cases here
}

func TestFileStoreLoadAppend(t *testing.T) {
	u1, _ := GetUser("alice", "fubar")
	data1 := userlib.RandomBytes(6400)
	err := u1.StoreFile("file1", data1)
	if err != nil {
		t.Error(err)
	}
	u2, _ := GetUser("alice", "fubar")
	data1a := userlib.RandomBytes(6400)
	err = u2.StoreFile("file2", data1a)
	if err != nil {
		t.Error(err)
	}
	data2, err2 := u1.LoadFile("file2", 0)
	if err2 != nil {
		t.Error(err2)
	}

	if !reflect.DeepEqual(data1a[0:64], data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted", data1[0:64], "\n", data1[64:128], "\n", data2)
	}

	// add test cases here
	v := userlib.RandomBytes(6400)
	err3 := u1.AppendFile("file1", v)
	if err3 != nil {
		t.Error("Append not successfull")
	}
	// data3, err5 := u1.LoadFile("file1",127)
	// if err5 != nil {
	// 	t.Error("Failed to load file", err5)
	// }
	// if !reflect.DeepEqual(data1[8128:8192], data3) {
	// 		t.Error("Downloaded file is not the same", data1[8128:8192], data3)
	// } else {
	// 	t.Log("Correct")
	// }
	data4, err6 := u2.LoadFile("file1",100)
	if err6 != nil {
		t.Error("Failed to load file", err6)
	}
	if !reflect.DeepEqual(v[0:64], data4) {
			t.Error("Downloaded file is not the same", v[0:64], "\n", "\n", data4)
	}
	data5, err7 := u1.LoadFile("file1",105)
	if err7 != nil {
		t.Error("Failed to load file", err7)
	}
	if !reflect.DeepEqual(v[320:384], data5) {
			t.Error("Downloaded file is not the same", v[320:384], "\n", data5)
	}
}

func TestFileShareReceive(t *testing.T) {
	// add test cases here
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1",0)
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2",0)
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

	err = u.RevokeFile("file1")
	if err != nil {
		t.Error("Failed to revoke", err)
	}

	v2, err = u2.LoadFile("file2",0)
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}