
#include <ctime>
#include <cstdlib>
#include <string>
#include <sstream>
#include <list>
#include <vector>
#include<fstream>
#include <iostream>
using namespace std;
const string filename = "passwords.txt";

/*
	Class: RSACipher
    This class implements the RSA encryption 
	and decryption algorithm.
    It provides methods to generate RSA keys, 
	encrypt messages, and decrypt messages.
*/

class RSACipher{
public:
	// Static members to hold prime numbers (p,q), modulus (n), 
	// public exponent (e), and private exponent (d)
	static int p, q, n, e, d;
	    
	// this method computes the greatest common divisor of two numbers
	static int gcd(int num1, int num2) {
		if (num2 == 0)
			return num1;
		return gcd(num2, num1 % num2);
	}

	/**
	This function generates RSA encryption and decryption keys.
    It calculates the modulus 'n', 
	public exponent 'e', and private exponent 'd'.
    It iterates through possible values of 'e' 
	and 'd' until finding ones that satisfy RSA requirements.
	*/
	static void generateKeys() {
		n = p * q;
		int phi = (p - 1) * (q - 1);
		for (e = 2; e < phi; e++) {
			if (gcd(e, phi) == 1)
				break;
		}
		for (d = 2; d < phi; d++) {
			if ((d * e) % phi == 1)
				break;
		}
	}

	static long long int modExp(long long int base, long long int exponent, long long int modulus) {
		long long int result = 1;
		base = base % modulus;
		while (exponent > 0) {
			if (exponent % 2 == 1)
				result = (result * base) % modulus;
			exponent = exponent >> 1;
			base = (base * base) % modulus;
		}
		return result;
	}
	static string encrypt(string message) {
		string encryptedMessage = "";
		for (char c : message) {
			long long int m = c;
			long long int cryptedCh = modExp(m, e, n);
			encryptedMessage += to_string(cryptedCh) + " ";
		}
		return encryptedMessage;
	}

	static string decrypt(string message) {
		string decryptedMassage = "";
		for (string::size_type i = 0; i < message.length(); i++) {
			string num_str = "";
			while (message[i] != ' ' && i < message.length()) {
				num_str += message[i];
				i++;
			}
			long long int crypted = stoll(num_str);
			long long int decrypted = modExp(crypted, d, n);
			decryptedMassage += static_cast<char>(decrypted);
		}
		return decryptedMassage;
	}
};

int RSACipher::p = 11;
int RSACipher::q = 13;
int RSACipher::n;
int RSACipher::e;
int RSACipher::d;

/**
This class represents a password entry in the password manager.
It stores the username, encrypted password, and an authorized key.
*/
class Password {
public:
    string user;
    string password;
    string authorizedKey;
};

/**
This class represents a node in the hash table.
It holds a password object and its associated key.
*/
class Node {
public:
    Password value;
    string key;
	Node(const string& key, const Password& value){
		this->value = value;
		this->key = key;
	}
};

/**
This class implements a hash table to store password entries.
*/
class HashTable {
private:
    vector<list<Node*>> hashTable;
    int size;
    int getHash(const string& key) const {
        return hash<string>()(key) % hashTable.size();
    }
public:
    HashTable(int initSize = 10) : size(0) {
        hashTable.resize(initSize);
    }

    ~HashTable() {
        clear();
    }

    void add(const string& key, const Password& value) {
		int index = getHash(key);
        for (Node* node : hashTable[index]) {
            if (node->key == key) {
                // user already exists, update his/her value
                node->value = value;
                return;
            }
        }
		//new user so add it
        hashTable[index].push_back(new Node(key,value));
        size++;
    }

    bool get(const string& key, Password& value) const {
		int index = getHash(key);
        for (Node* node : hashTable[index]) {
			if (node->key == key) {
                value = node->value;
                return true;
            }
        }
        return false;
    }

    bool contains(const string& key) {
		int index = getHash(key);
        for (Node* node : hashTable[index]) {
            if (node->key == key) {
                return true;
            }
        }
        return false;
    }

    void clear() {
		hashTable.clear();
        size = 0;
    }

	void writeData(){
		ofstream outFile(filename);
		string key;
		if (outFile.is_open()) {
			for(int index = 0 ; index < hashTable.size(); index++){
				for (Node* node : hashTable[index]) {
					if(node == NULL)
						continue;
					key = node->value.authorizedKey;
					outFile << node->key << "," << node->value.password << "," << key<<"\n";
				}
			}
			outFile.close();
			cout<<"Data has been written to file successfully\n";
		}
	}
};

/**
This class provides a secure password management system (SPMS).
It uses RSA encryption for storing passwords securely.
*/
class SecurePasswordManager {
private:
    HashTable sPMSHashTable;

public:

	SecurePasswordManager(){
		readData();
	}

	/**
	This function adds a new password entry 
	to the Secure Password Manager System (SPMS).
    It encrypts the password using RSA and stores 
	the username, encrypted password, and authorized key.
	*/
    void addnewPassWord(string user, string password, string authorizedKey) {
		password = RSACipher::encrypt(password);
		Password passwordObj;
		passwordObj.user = user;
		passwordObj.password = password;
		authorizedKey = RSACipher::encrypt(authorizedKey);
		passwordObj.authorizedKey = authorizedKey;
		sPMSHashTable.add(user, passwordObj);
        cout << "new Password added successfully Our To SPMS.\n";
    }

	/**
	This function retrieves an existing password 
	from the Secure Password Manager System (SPMS).
    It prompts the user for an authorized key 
	to decrypt the password and displays it.
	*/
    void getExistingPassWord(string user){
		if(sPMSHashTable.contains(user)){
			Password passwordObj;
			string authorizedKey;
			sPMSHashTable.get(user,passwordObj);
			cout<<"Cipher Text password of "<<user<<" is: "<<passwordObj.password<<endl;
			cout<<"Enter Authorized Key to display Plain Text password: ";
			getline(cin,authorizedKey);
			if(RSACipher::decrypt(passwordObj.authorizedKey) != authorizedKey){
				cout<<"Invalid Authorized Key of "<<user<<", so not allowed to display Plain Text password\n";
			}
			else{
				cout<<"Plain Text password of "<<user<<" is: "<<RSACipher::decrypt(passwordObj.password)<<endl;
			}
		}
		else{
			cout<<"User: "<<user<<" not exist in our SPMS\n";
		}
    }

	/**
	This function generates a random password of 
	the specified length.
    It randomly selects characters from the 
	alphabet to create the password.
	*/
    void createRandomPassword(int length) {
         string password = "";
		static const char charset[] = 
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=<>?";

		int charsetSize = sizeof(charset) - 1;

		for (int i = 0; i < length; ++i) {
			int index = rand() % charsetSize;
			password += charset[index];
		}

		cout << "Generated Random Password is: " << password << "\n";
    }

	/**
	This function reads data from a file during initialization 
	of the Secure Password Manager System (SPMS).
    It populates the hash table with password entries 
	stored in the file.
	*/
	void readData(){
		ifstream inFile(filename);
		if (inFile.is_open()) {
			cout<<"Loading data from file  ......\n";
			string line;
			Password passwordObj;
			while (getline(inFile, line)) {
				stringstream ss(line);
				string temp;
				getline(ss, passwordObj.user, ',');
				getline(ss, passwordObj.password, ',');
				getline(ss, passwordObj.authorizedKey, ',');
				sPMSHashTable.add(passwordObj.user, passwordObj);
			}
			inFile.close();
		}
	}
	/**
	This function writes data to a file before 
	closing the Secure Password Manager System (SPMS).
    It saves all password entries stored in 
	the hash table to a file.
	*/
	void writeData(){
		sPMSHashTable.writeData();
	}
};

/**
The main function of the program. 
It serves as the entry point and
orchestrates the interaction with 
the Secure Password Manager System (SPMS).
Steps:
1. Initializes the random seed.
2. Displays a welcome message.
3. Generates RSA keys using the RSACipher class.
4. Creates an instance of the SecurePasswordManager.
5. Enters a loop to display the main menu and process user input until the application is closed.
6. Provides options to add a new password, get an existing password, create a random password,
    or close the application.
7. Reads data from file during initialization.
8. Writes data to file before closing the application.
*/
int main() {
    srand(time(NULL));
    cout << "Welcome to Our Secure Password Manager System (SPMS)\n\n";
	RSACipher::generateKeys();
    SecurePasswordManager spm;
    bool closeApp;
	int choice, length;
	string user, password, key;
    for(closeApp = false ; closeApp != true;) {
        cout << "**** SPMS Main Menu ****\n";
        cout << "1. Add New Password\n";
        cout << "2. Get Existing Password\n";
        cout << "3. Create Random Password\n";
        cout << "0. Close Application\n";
        cout << "your choice [0-3]: ";
        cin >> choice;
        cin.ignore();
        switch (choice) {
			// Close Application
            case 0:
                closeApp = true;
                cout << "Closing Our Application. Goodbye\n";
                break;
			// Add New Password
            case 1: 
                cout << "Enter User Name: ";
                getline(cin, user);
                cout << "Enter Password: ";
                getline(cin, password);
                cout << "Please enter the key to display the decrypted password when required: ";
                getline(cin, key);
				spm.addnewPassWord(user, password, key);
                break;
            // Get Existing Password
            case 2: 
                cout << "Enter User Name: ";
                getline(cin, user);
                spm.getExistingPassWord(user);
                break;
            // Create Random Password
            case 3: 
                cout << "Enter password length you want: ";
                cin >> length;
				cin.ignore();
				spm.createRandomPassword (length);
                break;
            default:
                cout << "Invalid choice. try again [0-3].\n";
                break;
        }
    }
	
	spm.writeData();
	system("pause");
    return 0;
}
