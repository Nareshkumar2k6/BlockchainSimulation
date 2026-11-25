//==============================================================
//  BLOCKCHAIN SIMULATION (Improved Version) - DSA Project BCS-3J
//  Group : Naresh Kumar (25K-0712), Janmesh Kumar (25K-0529),
//          Abdul Samad (25K-0910)
//  Language : C++17
//  Compile  : g++ -std=c++17 -O2 BlockchainSimulation_v2.cpp -o blockchain
//
//  Data structures used:
//    1. Singly linked list  -> chain of blocks (one copy per node)
//    2. Queue               -> pending transactions
//    3. Hash table (chain)  -> account balances
//    4. Binary search tree  -> registered users
//    5. Vector of nodes     -> simulated nodes / voters
//==============================================================
#include <iostream>   // cin and cout: keyboard input and screen output
#include <string>     // string class: stores text
#include <vector>     // vector class: dynamic array
#include <ctime>      // time() and localtime(): current time and date text
#include <chrono>     // steady_clock: measure running time in tests
#include <sstream>    // ostringstream: builds the hash text
#include <iomanip>    // setw, setfill, setprecision: output formatting
#include <cstdint>    // uint32_t, uint64_t: fixed-size integers for SHA-256
#include <cmath>      // log10: used to draw the text graph
#include <fstream>    // ofstream: writes the export files
using namespace std;  // use standard names without writing std:: each time

//==============================================================
//  SETTINGS (constants)
//==============================================================
const int START_BALANCE    = 100;      // money every account starts with
const int MINING_REWARD    = 10;       // reward the miner gets per block
const int MAX_TX_PER_BLOCK = 3;        // maximum transactions in one block
const int MAX_DIFFICULTY   = 4;        // highest allowed mining difficulty
const int MAX_ATTEMPTS     = 1000000;  // mining stops after this many tries
const int HASH_SIZE        = 11;       // number of buckets in the hash table

//==============================================================
//  PART 1 : SHA-256 HASHING
//==============================================================
static const uint32_t K[64] = {                                                              // 64 fixed SHA-256 round constants (never change a digit)
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5, // constants for rounds 0-7
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174, // constants for rounds 8-15
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da, // constants for rounds 16-23
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967, // constants for rounds 24-31
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85, // constants for rounds 32-39
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070, // constants for rounds 40-47
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3, // constants for rounds 48-55
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2  // constants for rounds 56-63
}; // end of K array

// Rotate bits of x to the right
uint32_t rotr(uint32_t x, int n) {                                   // x = number, n = how many bits to rotate
    return (x >> n) | (x << (32 - n));                               // shift right, and wrap lost bits to the left
} // end of rotr

// Convert text into a SHA-256 hash (64 hex characters)
string sha256(const string& input) {                                 // input text -> hash text
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, // first 4 standard starting values
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};// last 4 standard starting values
    string msg = input;                                              // working copy of the input
    uint64_t bitLen = (uint64_t)input.size() * 8;                    // message length in bits
    msg += (char)0x80;                                               // padding: add one 1-bit (byte 0x80)
    while (msg.size() % 64 != 56) msg += (char)0;                    // padding: add zero bytes until size is 56 mod 64
    for (int i = 7; i >= 0; i--) msg += (char)((bitLen >> (i * 8)) & 0xff); // padding: add 8-byte length
    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {        // process message in 64-byte chunks
        uint32_t w[64];                                              // message schedule: 64 words
        for (int i = 0; i < 16; i++) {                               // first 16 words come from chunk bytes
            w[i] = ((uint32_t)(unsigned char)msg[chunk + i * 4] << 24) |     // byte 1 -> top 8 bits
                   ((uint32_t)(unsigned char)msg[chunk + i * 4 + 1] << 16) | // byte 2
                   ((uint32_t)(unsigned char)msg[chunk + i * 4 + 2] << 8) |  // byte 3
                   ((uint32_t)(unsigned char)msg[chunk + i * 4 + 3]);        // byte 4 -> bottom 8 bits
        } // end for (first 16 words)
        for (int i = 16; i < 64; i++) {                              // remaining 48 words are calculated
            uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);  // mixing step 1
            uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);   // mixing step 2
            w[i] = w[i-16] + s0 + w[i-7] + s1;                       // new word from older words
        } // end for (remaining words)
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];             // working variables a-d
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];            // working variables e-h
        for (int i = 0; i < 64; i++) {                               // 64 compression rounds
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);    // mix bits of e
            uint32_t ch = (e & f) ^ ((~e) & g);                      // choose function
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];                // temp value 1 (uses round constant)
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);    // mix bits of a
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);              // majority function
            uint32_t t2 = S0 + maj;                                  // temp value 2
            hh = g; g = f; f = e; e = d + t1;                        // shift variables e-h
            d = c; c = b; b = a; a = t1 + t2;                        // shift variables a-d
        } // end for (rounds)
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;                  // add result into hash values (part 1)
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;                 // add result into hash values (part 2)
    } // end for (chunks)
    ostringstream out;                                               // stream to build the hex text
    for (int i = 0; i < 8; i++) out << hex << setw(8) << setfill('0') << h[i]; // write each value as 8 hex digits
    return out.str();                                                // return the final 64-character hash
} // end of sha256

//==============================================================
//  PART 2 : RECORDS (User, Transaction, Block)
//==============================================================
struct User {                          // one registered user
    int userID;                        // unique ID (BST key)
    string displayName;                // name shown on screen
    int accountID;                     // account number used in the hash table
    bool activeStatus;                 // true = active node, false = inactive node
}; // end of User

struct Transaction {                   // one money transfer
    int transactionID;                 // unique ID of this transaction
    int senderID;                      // user who sends money
    int receiverID;                    // user who receives money
    int amount;                        // whole units only
    long long timestamp;               // time when it was created
}; // end of Transaction

struct Block {                         // one block of the chain (linked list node)
    int index = 0;                     // position of block in chain
    string previousHash;               // hash of the previous block
    vector<Transaction> txList;        // transactions stored in this block
    int minerID = 0;                   // user who mined this block
    int nonce = 0;                     // number tried during mining
    int difficulty = 0;                // required leading zeros in hash
    long long timestamp = 0;           // time when block was created
    string blockHash;                  // hash of this block
    Block* next = nullptr;             // pointer to the next block
}; // end of Block

// Convert a time number into readable date text
string timeToText(long long t) {                                     // t = seconds since 1970
    if (t == 0) return "fixed (genesis)";                            // genesis block uses a fixed time
    time_t raw = (time_t)t;                                          // convert to system time type
    char buffer[32];                                                 // space for the date text
    struct tm* info = localtime(&raw);                               // break time into year, month, day...
    if (info == nullptr) return to_string(t);                        // if conversion fails, show the number
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", info);     // format as YYYY-MM-DD HH:MM:SS
    return string(buffer);                                           // return the text
} // end of timeToText

// Convert one transaction to text
string txToString(const Transaction& t) {                            // used for hashing and comparing
    return to_string(t.transactionID) + ":" + to_string(t.senderID) + ":" +   // id and sender
           to_string(t.receiverID) + ":" + to_string(t.amount) + ":" +        // receiver and amount
           to_string(t.timestamp);                                            // creation time
} // end of txToString

// Convert block data to text (always the same order)
string blockToString(const Block& b) {                               // text that will be hashed
    string s = to_string(b.index) + "|" + b.previousHash + "|";      // start with index and previous hash
    for (size_t i = 0; i < b.txList.size(); i++) s += txToString(b.txList[i]) + ";"; // add every transaction in order
    s += "|" + to_string(b.minerID) + "|" + to_string(b.nonce) + "|" +  // add miner and nonce
         to_string(b.difficulty) + "|" + to_string(b.timestamp);        // add difficulty and time
    return s;                                                        // return full block text
} // end of blockToString

// Calculate hash of a block
string calculateHash(const Block& b) {                               // block -> hash
    return sha256(blockToString(b));                                 // hash the block text
} // end of calculateHash

// Check that hash starts with d zeros
bool hasLeadingZeros(const string& hash, int d) {                    // d = required zeros
    for (int i = 0; i < d; i++)                                      // check first d characters
        if (hash[i] != '0') return false;                            // any non-zero means failure
    return true;                                                     // all were zeros
} // end of hasLeadingZeros

// Create the fixed genesis block
Block makeGenesis() {                                                // same genesis for every node
    Block g;                                                         // new empty block
    g.index = 0;                                                     // genesis is block 0
    g.previousHash = "0";                                            // no previous block
    g.minerID = 0;                                                   // nobody mined it
    g.nonce = 0;                                                     // no mining needed
    g.difficulty = 0;                                                // no difficulty for genesis
    g.timestamp = 0;                                                 // fixed time so all nodes match
    g.blockHash = calculateHash(g);                                  // calculate its hash
    return g;                                                        // give it back
} // end of makeGenesis

// Shorten a long hash for display
string shortHash(const string& h) {                                  // h = full hash
    if (h.size() <= 12) return h;                                    // already short
    return h.substr(0, 12) + "...";                                  // first 12 characters + dots
} // end of shortHash

// Add spaces to the right of text (for tables)
string pad(const string& s, size_t width) {                          // width = wanted length
    string r = s;                                                    // copy the text
    while (r.size() < width) r += ' ';                               // add spaces until wide enough
    return r;                                                        // return padded text
} // end of pad

// Make a text bar like ##### for graphs
string bar(int n) {                                                  // n = bar length
    return string(n > 0 ? n : 0, '#');                               // n hash symbols (never negative)
} // end of bar

//==============================================================
//  PART 3 : BINARY SEARCH TREE (users indexed by userID)
//==============================================================
struct BSTNode {                       // one node of the tree
    User data;                         // user stored here
    BSTNode* left;                     // smaller IDs go left
    BSTNode* right;                    // bigger IDs go right
}; // end of BSTNode

class UserBST {                                                      // tree class for users
private:                                                             // hidden members
    BSTNode* root;                                                   // top node of the tree
    int count;                                                       // number of users stored

    // Delete all nodes of a subtree
    void destroy(BSTNode* n) {                                       // n = subtree root
        if (n == nullptr) return;                                    // nothing to delete
        destroy(n->left);                                            // delete left side
        destroy(n->right);                                           // delete right side
        delete n;                                                    // delete this node
    } // end of destroy

    // Print users in sorted order
    void inOrderPrint(BSTNode* n) {                                  // n = subtree root
        if (n == nullptr) return;                                    // empty subtree
        inOrderPrint(n->left);                                       // smaller IDs first
        cout << "  ID: " << n->data.userID << " | Name: " << n->data.displayName      // print ID and name
             << " | Account: " << n->data.accountID << " | Status: "                  // print account number
             << (n->data.activeStatus ? "ACTIVE" : "INACTIVE") << "\n";               // print node status
        inOrderPrint(n->right);                                      // bigger IDs last
    } // end of inOrderPrint

    // Collect users in sorted order
    void inOrderCollect(BSTNode* n, vector<User*>& out) {            // out = result list
        if (n == nullptr) return;                                    // empty subtree
        inOrderCollect(n->left, out);                                // left side first
        out.push_back(&n->data);                                     // then this user
        inOrderCollect(n->right, out);                               // right side last
    } // end of inOrderCollect

public:                                                              // usable from outside
    UserBST() : root(nullptr), count(0) {}                           // start with an empty tree
    ~UserBST() { destroy(root); }                                    // free memory at the end
    UserBST(const UserBST&) = delete;                                // forbid copying the tree
    UserBST& operator=(const UserBST&) = delete;                     // forbid assigning the tree

    // Search a user by ID
    User* search(int id) {                                           // returns nullptr if not found
        BSTNode* cur = root;                                         // start at the top
        while (cur != nullptr) {                                     // walk down the tree
            if (id == cur->data.userID) return &cur->data;           // found the user
            if (id < cur->data.userID) cur = cur->left;              // smaller: go left
            else cur = cur->right;                                   // bigger: go right
        } // end while
        return nullptr;                                              // not in the tree
    } // end of search

    // Insert a new user (false if ID already exists)
    bool insert(const User& u) {                                     // u = user to add
        if (search(u.userID) != nullptr) return false;               // duplicate ID rejected
        BSTNode* newNode = new BSTNode{u, nullptr, nullptr};         // create the new node
        if (root == nullptr) {                                       // tree is empty
            root = newNode;                                          // new node becomes the root
        } else {                                                     // tree is not empty
            BSTNode* cur = root;                                     // start at the top
            while (true) {                                           // find the correct empty place
                if (u.userID < cur->data.userID) {                   // smaller ID goes left
                    if (cur->left == nullptr) { cur->left = newNode; break; }   // free spot: attach here
                    cur = cur->left;                                 // otherwise keep going left
                } else {                                             // bigger ID goes right
                    if (cur->right == nullptr) { cur->right = newNode; break; } // free spot: attach here
                    cur = cur->right;                                // otherwise keep going right
                } // end if-else
            } // end while
        } // end if-else
        count++;                                                     // one more user
        return true;                                                 // inserted successfully
    } // end of insert

    // Show all users sorted by ID
    void inOrder() { inOrderPrint(root); }                           // public wrapper for in-order print

    // Get all users as a list
    void collectUsers(vector<User*>& out) {                          // fills out with sorted users
        out.clear();                                                 // empty the list first
        inOrderCollect(root, out);                                   // fill it in sorted order
    } // end of collectUsers

    // Delete all users
    void clear() {                                                   // used by reset
        destroy(root);                                               // free all nodes
        root = nullptr;                                              // tree is empty again
        count = 0;                                                   // no users left
    } // end of clear

    // Number of users
    int size() const { return count; }                               // return user count
}; // end of class UserBST

//==============================================================
//  PART 4 : QUEUE (pending transactions, linked list based)
//==============================================================
struct QNode {                         // one node of the queue
    Transaction data;                  // transaction stored here
    QNode* next;                       // next waiting transaction
}; // end of QNode

class TxQueue {                                                      // FIFO queue class
private:                                                             // hidden members
    QNode* front;                                                    // first item (leaves first)
    QNode* rear;                                                     // last item (newest)
    int count;                                                       // number of items

public:                                                              // usable from outside
    TxQueue() : front(nullptr), rear(nullptr), count(0) {}           // start empty
    ~TxQueue() { clear(); }                                          // free memory at the end
    TxQueue(const TxQueue&) = delete;                                // forbid copying
    TxQueue& operator=(const TxQueue&) = delete;                     // forbid assigning

    // Add transaction at the end
    void enqueue(const Transaction& t) {                             // t = new transaction
        QNode* n = new QNode{t, nullptr};                            // create the node
        if (rear == nullptr) front = n;                              // first item: it is also the front
        else rear->next = n;                                         // otherwise link after the old rear
        rear = n;                                                    // new node is now the rear
        count++;                                                     // one more item
    } // end of enqueue

    // Look at the first transaction (no removal)
    bool peek(Transaction& out) {                                    // out receives a copy
        if (front == nullptr) return false;                          // queue is empty
        out = front->data;                                           // copy the first item
        return true;                                                 // success
    } // end of peek

    // Remove the first transaction
    bool dequeue(Transaction& out) {                                 // out receives removed item
        if (front == nullptr) return false;                          // queue is empty
        QNode* temp = front;                                         // remember the old front
        out = temp->data;                                            // copy its data
        front = front->next;                                         // move front forward
        if (front == nullptr) rear = nullptr;                        // queue became empty
        delete temp;                                                 // free the old node
        count--;                                                     // one less item
        return true;                                                 // success
    } // end of dequeue

    // Remove everything
    void clear() {                                                   // empty the queue
        Transaction t;                                               // dummy variable
        while (dequeue(t)) {}                                        // dequeue until empty
    } // end of clear

    // Check if queue is empty
    bool isEmpty() const { return count == 0; }                      // true when no items

    // Number of pending transactions
    int size() const { return count; }                               // return item count

    // Copy first n items (nothing is removed)
    vector<Transaction> firstN(int n) {                              // n = how many to copy
        vector<Transaction> result;                                  // list to return
        QNode* cur = front;                                          // start at the front
        while (cur != nullptr && (int)result.size() < n) {           // until end or n items copied
            result.push_back(cur->data);                             // copy this item
            cur = cur->next;                                         // go to next item
        } // end while
        return result;                                               // give the copied list
    } // end of firstN

    // Total pending money of one sender
    int pendingOutgoing(int senderID) {                              // senderID = user to check
        int total = 0;                                               // running total
        for (QNode* cur = front; cur != nullptr; cur = cur->next)    // visit every pending item
            if (cur->data.senderID == senderID) total += cur->data.amount; // add this sender's amounts
        return total;                                                // return the sum
    } // end of pendingOutgoing

    // Show pending list in arrival order
    void display() {                                                 // print the queue
        if (front == nullptr) { cout << "  (queue is empty)\n"; return; } // nothing to show
        int pos = 1;                                                 // position counter
        for (QNode* cur = front; cur != nullptr; cur = cur->next) {  // visit every item
            cout << "  " << pos++ << ". Tx#" << cur->data.transactionID << "  "   // position and ID
                 << cur->data.senderID << " -> " << cur->data.receiverID          // sender and receiver
                 << "  amount: " << cur->data.amount << "\n";                      // amount
        } // end for
    } // end of display
}; // end of class TxQueue

//==============================================================
//  PART 5 : HASH TABLE WITH CHAINING (accountID -> balance)
//==============================================================
struct HNode {                         // one entry in a bucket chain
    int accountID;                     // key
    int balance;                       // value
    HNode* next;                       // next entry in same bucket
}; // end of HNode

class BalanceTable {                                                 // hash table class
private:                                                             // hidden members
    HNode* buckets[HASH_SIZE];                                       // array of chain heads

    // Hash function: key -> bucket number
    int hashFunction(int key) const { return key % HASH_SIZE; }      // remainder picks the bucket

public:                                                              // usable from outside
    BalanceTable() { for (int i = 0; i < HASH_SIZE; i++) buckets[i] = nullptr; } // all buckets start empty
    ~BalanceTable() { clear(); }                                     // free memory at the end
    BalanceTable(const BalanceTable&) = delete;                      // forbid copying
    BalanceTable& operator=(const BalanceTable&) = delete;           // forbid assigning

    // Remove all entries
    void clear() {                                                   // empty the table
        for (int i = 0; i < HASH_SIZE; i++) {                        // go through each bucket
            HNode* cur = buckets[i];                                 // first entry of this bucket
            while (cur != nullptr) {                                 // walk the chain
                HNode* temp = cur;                                   // remember current entry
                cur = cur->next;                                     // move to next entry
                delete temp;                                         // free remembered entry
            } // end while
            buckets[i] = nullptr;                                    // bucket is empty now
        } // end for
    } // end of clear

    // Find an account entry
    HNode* find(int accountID) {                                     // returns nullptr if missing
        HNode* cur = buckets[hashFunction(accountID)];               // start of the correct chain
        while (cur != nullptr) {                                     // walk the chain
            if (cur->accountID == accountID) return cur;             // found it
            cur = cur->next;                                         // try next entry
        } // end while
        return nullptr;                                              // not found
    } // end of find

    // Insert an account (or update if it exists)
    void insert(int accountID, int balance) {                        // key and value
        HNode* existing = find(accountID);                           // already stored?
        if (existing != nullptr) { existing->balance = balance; return; } // yes: just update value
        int i = hashFunction(accountID);                             // choose the bucket
        buckets[i] = new HNode{accountID, balance, buckets[i]};      // add new entry at the chain head (handles collisions)
    } // end of insert

    // Update balance of an existing account
    bool update(int accountID, int newBalance) {                     // returns false if missing
        HNode* e = find(accountID);                                  // look for the entry
        if (e == nullptr) return false;                              // not found
        e->balance = newBalance;                                     // store new balance
        return true;                                                 // success
    } // end of update

    // Copy all entries from another table
    void copyFrom(const BalanceTable& other) {                       // other = source table
        if (this == &other) return;                                  // copying itself is useless
        clear();                                                     // remove old entries
        for (int i = 0; i < HASH_SIZE; i++)                          // each bucket of the source
            for (HNode* cur = other.buckets[i]; cur != nullptr; cur = cur->next) // each entry in chain
                insert(cur->accountID, cur->balance);                // copy the entry
    } // end of copyFrom

    // Show buckets and their chains
    void display() {                                                 // print the whole table
        for (int i = 0; i < HASH_SIZE; i++) {                        // each bucket
            cout << "  Bucket " << setw(2) << i << ": ";             // bucket number
            if (buckets[i] == nullptr) cout << "(empty)";            // nothing in this bucket
            for (HNode* cur = buckets[i]; cur != nullptr; cur = cur->next) { // each entry
                cout << "[Acc " << cur->accountID << " = " << cur->balance << "]"; // print entry
                if (cur->next != nullptr) cout << " -> ";            // arrow shows a collision chain
            } // end for
            cout << "\n";                                            // end of bucket line
        } // end for
    } // end of display
}; // end of class BalanceTable

//==============================================================
//  PART 6 : LINKED LIST OF BLOCKS (the blockchain copy)
//==============================================================
class Chain {                                                        // singly linked list of blocks
private:                                                             // hidden members
    Block* head;                                                     // first block (genesis)
    Block* tail;                                                     // last block (newest)
    int length;                                                      // number of blocks

public:                                                              // usable from outside
    Chain() : head(nullptr), tail(nullptr), length(0) {}             // start empty
    ~Chain() { clear(); }                                            // free memory at the end
    Chain(const Chain&) = delete;                                    // forbid copying
    Chain& operator=(const Chain&) = delete;                         // forbid assigning

    // Add a copy of a block at the end
    void append(const Block& b) {                                    // b = block to copy
        Block* n = new Block(b);                                     // make a new block copy
        n->next = nullptr;                                           // it is the last block
        if (head == nullptr) head = tail = n;                        // first block: head and tail
        else { tail->next = n; tail = n; }                           // otherwise link after old tail
        length++;                                                    // one more block
    } // end of append

    // Delete all blocks
    void clear() {                                                   // empty the chain
        Block* cur = head;                                           // start at the first block
        while (cur != nullptr) {                                     // walk the list
            Block* temp = cur;                                       // remember current block
            cur = cur->next;                                         // move to next block
            delete temp;                                             // free remembered block
        } // end while
        head = tail = nullptr;                                       // list is empty
        length = 0;                                                  // no blocks left
    } // end of clear

    // Make a deep copy of another chain
    void copyFrom(const Chain& other) {                              // other = source chain
        if (this == &other) return;                                  // copying itself is useless
        clear();                                                     // remove old blocks
        for (Block* cur = other.head; cur != nullptr; cur = cur->next) // each block of source
            append(*cur);                                            // copy it to the end
    } // end of copyFrom

    // Find a block by its index (traversal)
    Block* getBlock(int index) const {                               // returns nullptr if missing
        for (Block* cur = head; cur != nullptr; cur = cur->next)     // walk the list
            if (cur->index == index) return cur;                     // found the block
        return nullptr;                                              // no such block
    } // end of getBlock

    Block* getHead() const { return head; }                          // first block
    Block* getTail() const { return tail; }                          // last block
    int size() const { return length; }                              // number of blocks
}; // end of class Chain

//==============================================================
//  PART 7 : NODE + GLOBAL SIMULATION DATA
//==============================================================
struct Node {                          // one simulated node (belongs to one user)
    int userID = 0;                    // owner user ID
    Chain chain;                       // this node's own blockchain copy
    BalanceTable balances;             // this node's own balance table
    int latestAcceptedIndex = 0;       // index of newest accepted block
    int votesYes = 0;                  // how many times it voted YES
    int votesNo = 0;                   // how many times it voted NO
}; // end of Node

UserBST users;                         // all registered users (BST)
vector<Node*> nodes;                   // all simulated nodes
TxQueue pendingQueue;                  // transactions waiting for mining
int nextTxID = 1;                      // next unique transaction ID
int difficulty = 2;                    // current mining difficulty
Block candidate;                       // block that was mined and waits for voting
bool hasCandidate = false;             // true when a candidate exists
vector<string> recoveryLog;            // list of recovery events
vector<string> activityLog;            // list of all important events
bool inputEnded = false;               // true when keyboard input is finished

//==============================================================
//  PART 8 : INPUT, TIME AND LOG HELPERS
//==============================================================
// Read one full line from the user
string readLine(const string& prompt) {                              // prompt = message to show
    cout << prompt;                                                  // show the message
    string s;                                                        // place for the typed text
    if (!getline(cin, s)) { inputEnded = true; return ""; }          // input finished: remember it
    return s;                                                        // return what user typed
} // end of readLine

// Read a whole number safely
bool readInt(const string& prompt, int& value) {                     // value receives the number
    string s = readLine(prompt);                                     // read text
    if (inputEnded) return false;                                    // no input left
    size_t a = s.find_first_not_of(" \t\r");                         // first non-space position
    size_t b = s.find_last_not_of(" \t\r");                          // last non-space position
    if (a == string::npos) { cout << "Invalid input: nothing entered.\n"; return false; } // only spaces typed
    s = s.substr(a, b - a + 1);                                      // remove spaces at both ends
    size_t start = (s[0] == '-') ? 1 : 0;                            // allow one minus sign
    if (start == s.size() || s.size() - start > 9) {                 // no digits, or too many digits
        cout << "Invalid input: please enter a whole number.\n";     // show error
        return false;                                                // stop
    } // end if
    for (size_t i = start; i < s.size(); i++) {                      // check each remaining character
        if (s[i] < '0' || s[i] > '9') {                              // not a digit
            cout << "Invalid input: please enter a whole number.\n"; // show error
            return false;                                            // stop
        } // end if
    } // end for
    value = stoi(s);                                                 // convert text to number
    return true;                                                     // success
} // end of readInt

// Ask a yes/no question
bool readYesNo(const string& prompt) {                               // true only for y / yes
    string s = readLine(prompt);                                     // read the answer
    return (s == "y" || s == "Y" || s == "yes" || s == "YES");       // accepted yes forms
} // end of readYesNo

// Current time in microseconds (for timing)
double nowMicros() {                                                 // used by performance tests
    return chrono::duration<double, micro>(                          // convert to microseconds
        chrono::steady_clock::now().time_since_epoch()).count();     // time since clock start
} // end of nowMicros

// Save an event in the activity log
void logEvent(const string& text) {                                  // text = what happened
    activityLog.push_back("[" + timeToText((long long)time(nullptr)) + "] " + text); // add time + text
} // end of logEvent

//==============================================================
//  PART 9 : USER / NODE MANAGER HELPERS
//==============================================================
// Find a node by user ID
Node* findNode(int userID) {                                         // returns nullptr if missing
    for (size_t i = 0; i < nodes.size(); i++)                        // check every node
        if (nodes[i]->userID == userID) return nodes[i];             // found it
    return nullptr;                                                  // no such node
} // end of findNode

// Find the account ID of a user
int accountOf(int userID) {                                          // returns -1 if user unknown
    User* u = users.search(userID);                                  // BST search
    if (u == nullptr) return -1;                                     // not registered
    return u->accountID;                                             // return account number
} // end of accountOf

// Check if a user's node is active
bool isActive(int userID) {                                          // true = active
    User* u = users.search(userID);                                  // BST search
    return (u != nullptr && u->activeStatus);                        // must exist and be active
} // end of isActive

// Give every registered account the start balance
void resetBalances(BalanceTable& table) {                            // table = table to fill
    table.clear();                                                   // remove old data
    vector<User*> all;                                               // list of users
    users.collectUsers(all);                                         // get users in sorted order
    for (size_t i = 0; i < all.size(); i++)                          // every user
        table.insert(all[i]->accountID, START_BALANCE);              // account starts with 100
} // end of resetBalances

// Ask for a node ID and find that node
Node* askNode(const string& prompt) {                                // returns nullptr on error
    int id;                                                          // typed ID
    if (!readInt(prompt, id)) return nullptr;                        // invalid number
    Node* n = findNode(id);                                          // look for the node
    if (n == nullptr) cout << "Error: no node found for user ID " << id << ".\n"; // not found message
    return n;                                                        // node or nullptr
} // end of askNode

//==============================================================
//  PART 10 : LEDGER VALIDATION (blocks + balances)
//==============================================================
// Check and apply the transfers of a block to a table
bool applyBlock(const Block& b, BalanceTable& table, string& reason) {   // reason = error text
    for (size_t i = 0; i < b.txList.size(); i++) {                   // every transaction in the block
        const Transaction& t = b.txList[i];                          // short name for current one
        User* s = users.search(t.senderID);                          // find sender
        User* r = users.search(t.receiverID);                        // find receiver
        if (s == nullptr || r == nullptr) {                          // someone not registered
            reason = "Tx#" + to_string(t.transactionID) + " has unregistered user"; // set reason
            return false;                                            // block invalid
        } // end if
        if (t.senderID == t.receiverID) {                            // self-transfer
            reason = "Tx#" + to_string(t.transactionID) + " is a self-transfer";    // set reason
            return false;                                            // block invalid
        } // end if
        if (t.amount <= 0) {                                         // zero or negative amount
            reason = "Tx#" + to_string(t.transactionID) + " has non-positive amount"; // set reason
            return false;                                            // block invalid
        } // end if
        HNode* sb = table.find(s->accountID);                        // sender's balance entry
        HNode* rb = table.find(r->accountID);                        // receiver's balance entry
        if (sb == nullptr || rb == nullptr) {                        // account missing in table
            reason = "Tx#" + to_string(t.transactionID) + " account not in balance table"; // set reason
            return false;                                            // block invalid
        } // end if
        if (sb->balance < t.amount) {                                // sender cannot pay
            reason = "Tx#" + to_string(t.transactionID) + " sender has insufficient balance"; // set reason
            return false;                                            // block invalid
        } // end if
        table.update(s->accountID, sb->balance - t.amount);          // take money from sender
        table.update(r->accountID, rb->balance + t.amount);          // give money to receiver
    } // end for
    if (b.index > 0) {                                               // genesis has no reward
        User* m = users.search(b.minerID);                           // find the miner
        if (m == nullptr) { reason = "Miner is not registered"; return false; } // unknown miner
        HNode* mb = table.find(m->accountID);                        // miner's balance entry
        if (mb == nullptr) { reason = "Miner account missing"; return false; }  // missing account
        table.update(m->accountID, mb->balance + MINING_REWARD);     // pay mining reward
    } // end if
    return true;                                                     // block applied correctly
} // end of applyBlock

// Check one block against the previous block
bool checkBlockLinks(const Block& b, const Block& prev, string& reason) { // reason = error text
    if (b.index != prev.index + 1) { reason = "wrong block index"; return false; }                   // index must go up by 1
    if (b.previousHash != prev.blockHash) { reason = "previous hash link is broken"; return false; } // link must match
    if (calculateHash(b) != b.blockHash) { reason = "block data changed (hash mismatch)"; return false; } // data must match hash
    if (b.difficulty < 1 || b.difficulty > MAX_DIFFICULTY) { reason = "difficulty not allowed"; return false; } // difficulty range
    if (!hasLeadingZeros(b.blockHash, b.difficulty)) { reason = "hash does not match difficulty"; return false; } // proof of work
    return true;                                                     // block is fine
} // end of checkBlockLinks

// Print a failure message (if verbose) and return false
bool failMsg(bool verbose, const string& text) {                     // verbose = show message?
    if (verbose) cout << "   [FAIL] " << text << "\n";               // print the reason
    return false;                                                    // always false
} // end of failMsg

// Validate the full chain of a node
bool validateChain(Node* n, bool verbose) {                          // true = chain is fully valid
    Block* cur = n->chain.getHead();                                 // start at genesis
    if (cur == nullptr) return failMsg(verbose, "Chain is empty.");  // empty chain is invalid
    Block genesis = makeGenesis();                                   // the agreed genesis
    if (cur->blockHash != genesis.blockHash || calculateHash(*cur) != cur->blockHash) // genesis must match
        return failMsg(verbose, "Genesis block is different from the agreed genesis.");  // report problem
    BalanceTable replay;                                             // table to replay history
    resetBalances(replay);                                           // start from genesis balances
    vector<int> seenIDs;                                             // transaction IDs already seen
    Block* prev = cur;                                               // previous block pointer
    cur = cur->next;                                                 // move to block 1
    while (cur != nullptr) {                                         // check every block
        string reason;                                               // error text
        if (!checkBlockLinks(*cur, *prev, reason))                   // check hash, link, difficulty
            return failMsg(verbose, "Block " + to_string(cur->index) + ": " + reason); // report problem
        for (size_t i = 0; i < cur->txList.size(); i++) {            // check duplicate transaction IDs
            int id = cur->txList[i].transactionID;                   // this transaction's ID
            for (size_t j = 0; j < seenIDs.size(); j++)              // compare with earlier IDs
                if (seenIDs[j] == id)                                // same ID found twice
                    return failMsg(verbose, "Block " + to_string(cur->index) + ": duplicate transaction ID " + to_string(id)); // report problem
            seenIDs.push_back(id);                                   // remember this ID
        } // end for
        if (!applyBlock(*cur, replay, reason))                       // replay the transfers
            return failMsg(verbose, "Block " + to_string(cur->index) + ": " + reason); // report problem
        prev = cur;                                                  // current becomes previous
        cur = cur->next;                                             // go to next block
    } // end while
    if (n->latestAcceptedIndex != n->chain.getTail()->index)         // stored index must match the tip
        return failMsg(verbose, "Latest accepted index does not match chain tip."); // report problem
    vector<User*> all;                                               // list of users
    users.collectUsers(all);                                         // get all users
    for (size_t i = 0; i < all.size(); i++) {                        // compare balances user by user
        HNode* a = replay.find(all[i]->accountID);                   // balance from replay
        HNode* b = n->balances.find(all[i]->accountID);              // balance stored in node
        if (a == nullptr || b == nullptr || a->balance != b->balance) // they must be equal
            return failMsg(verbose, "Balance table does not match history for user " + to_string(all[i]->userID)); // report problem
    } // end for
    return true;                                                     // everything is consistent
} // end of validateChain

// Rebuild balances of a node from its chain history
bool rebuildBalances(Node* n) {                                      // true = success
    resetBalances(n->balances);                                      // start from genesis balances
    for (Block* cur = n->chain.getHead(); cur != nullptr; cur = cur->next) { // each block
        if (cur->index == 0) continue;                               // skip genesis
        string reason;                                               // error text
        if (!applyBlock(*cur, n->balances, reason)) return false;    // replay failed
    } // end for
    return true;                                                     // rebuilt successfully
} // end of rebuildBalances

// Find the best valid node (longest valid chain)
Node* findReferenceNode(Node* exclude) {                             // exclude = node to skip
    Node* best = nullptr;                                            // best node so far
    for (size_t i = 0; i < nodes.size(); i++) {                      // check every node
        Node* n = nodes[i];                                          // current node
        if (n == exclude) continue;                                  // skip excluded node
        if (!validateChain(n, false)) continue;                      // skip invalid nodes
        if (best == nullptr || n->latestAcceptedIndex > best->latestAcceptedIndex) // longer chain wins
            best = n;                                                // new best node
    } // end for
    return best;                                                     // may be nullptr
} // end of findReferenceNode

//==============================================================
//  PART 11 : DISPLAY HELPERS
//==============================================================
// Print one block's details
void printBlock(const Block& b, bool fullHash) {                     // fullHash = show whole hash?
    cout << "  +-- Block " << b.index << (b.index == 0 ? " (Genesis)" : "") << "\n";   // block number
    cout << "  | Previous Hash : " << (fullHash ? b.previousHash : shortHash(b.previousHash)) << "\n"; // previous hash
    cout << "  | Miner ID      : " << b.minerID << "\n";            // miner
    cout << "  | Nonce         : " << b.nonce << "\n";              // nonce
    cout << "  | Difficulty    : " << b.difficulty << "\n";         // difficulty
    cout << "  | Time          : " << timeToText(b.timestamp) << "\n"; // readable time
    cout << "  | Block Hash    : " << (fullHash ? b.blockHash : shortHash(b.blockHash)) << "\n"; // hash
    cout << "  | Transactions  : " << b.txList.size() << "\n";      // how many transactions
    for (size_t i = 0; i < b.txList.size(); i++) {                   // each transaction
        const Transaction& t = b.txList[i];                          // short name
        cout << "  |    Tx#" << t.transactionID << "  " << t.senderID << " -> "  // ID and sender
             << t.receiverID << "  amount: " << t.amount << "\n";   // receiver and amount
    } // end for
} // end of printBlock

// Show balances of all users from one node's table
void printAllBalances(Node* n) {                                     // n = node to read from
    vector<User*> all;                                               // list of users
    users.collectUsers(all);                                         // get all users
    cout << "Balances on node " << n->userID << ":\n";               // heading
    for (size_t i = 0; i < all.size(); i++) {                        // each user
        HNode* e = n->balances.find(all[i]->accountID);              // hash table lookup
        cout << "  User " << all[i]->userID << " (" << all[i]->displayName << ") account "  // who
             << all[i]->accountID << ": confirmed " << (e != nullptr ? e->balance : 0)     // confirmed money
             << " | pending out " << pendingQueue.pendingOutgoing(all[i]->userID) << "\n"; // waiting payments
    } // end for
} // end of printAllBalances

// Show two node copies side by side
void printComparison(Node* a, Node* b) {                             // a and b = nodes to compare
    cout << "Side-by-side comparison: node " << a->userID << " vs node " << b->userID << "\n"; // heading
    cout << "  " << pad("Block", 7) << pad("Node " + to_string(a->userID), 18)     // column titles
         << pad("Node " + to_string(b->userID), 18) << "Same?\n";                  // last column title
    int lenA = a->chain.size();                                      // length of chain A
    int lenB = b->chain.size();                                      // length of chain B
    int maxLen = (lenA > lenB) ? lenA : lenB;                        // longer length
    for (int i = 0; i < maxLen; i++) {                               // each block position
        Block* x = a->chain.getBlock(i);                             // block i in A
        Block* y = b->chain.getBlock(i);                             // block i in B
        string sx = (x != nullptr) ? shortHash(x->blockHash) : "(missing)"; // text for A
        string sy = (y != nullptr) ? shortHash(y->blockHash) : "(missing)"; // text for B
        bool same = (x != nullptr && y != nullptr && x->blockHash == y->blockHash); // equal hashes?
        cout << "  " << pad(to_string(i), 7) << pad(sx, 18) << pad(sy, 18) << (same ? "yes" : "NO") << "\n"; // print row
    } // end for
    cout << "  Chain valid? node " << a->userID << ": " << (validateChain(a, false) ? "yes" : "NO")   // validity of A
         << " | node " << b->userID << ": " << (validateChain(b, false) ? "yes" : "NO") << "\n";     // validity of B
    vector<User*> all;                                               // list of users
    users.collectUsers(all);                                         // get all users
    cout << "  Balances (user: node " << a->userID << " | node " << b->userID << "):\n"; // heading
    for (size_t i = 0; i < all.size(); i++) {                        // each user
        HNode* p = a->balances.find(all[i]->accountID);              // balance in A
        HNode* q = b->balances.find(all[i]->accountID);              // balance in B
        int pv = (p != nullptr) ? p->balance : 0;                    // value in A
        int qv = (q != nullptr) ? q->balance : 0;                    // value in B
        cout << "    User " << all[i]->userID << ": " << pv << " | " << qv     // print both values
             << (pv != qv ? "   <-- different" : "") << "\n";       // mark differences
    } // end for
} // end of printComparison

//==============================================================
//  PART 12 : NODE CREATION, SYNCHRONIZATION, RESET
//==============================================================
// Create a node that has only the genesis block
Node* createNode(int userID) {                                       // userID = owner
    Node* n = new Node();                                            // make a new node
    n->userID = userID;                                              // set owner
    n->chain.append(makeGenesis());                                  // every node starts with the same genesis
    n->latestAcceptedIndex = 0;                                      // tip is genesis
    resetBalances(n->balances);                                      // start balances
    nodes.push_back(n);                                              // add to node list
    return n;                                                        // give it back
} // end of createNode

// Verify and update a node's own copy
bool syncNode(Node* n, bool verbose) {                               // verbose = print messages
    if (!validateChain(n, verbose)) {                                // step 1: verify own copy
        if (verbose) cout << "  Node " << n->userID << " has an invalid chain. Use 'Recover node' instead.\n"; // advice
        return false;                                                // cannot sync a bad chain
    } // end if
    Node* ref = findReferenceNode(nullptr);                          // step 2: find best valid chain
    if (ref == nullptr) {                                            // nobody is valid
        if (verbose) cout << "  No valid reference chain available.\n"; // message
        return false;                                                // stop
    } // end if
    Block* myTip = n->chain.getTail();                               // my newest block
    Block* refTip = ref->chain.getTail();                            // reference newest block
    if (n->latestAcceptedIndex == ref->latestAcceptedIndex) {        // same length
        if (myTip->blockHash == refTip->blockHash) {                 // same tip hash
            if (verbose) cout << "  Node " << n->userID << " is already up to date (tip index " << n->latestAcceptedIndex << ").\n"; // message
            return true;                                             // nothing to do
        } // end if
        if (verbose) cout << "  Conflict: same length but different tip. Use 'Recover node'.\n"; // fork detected
        return false;                                                // stop
    } // end if
    Block* refBlock = ref->chain.getBlock(n->latestAcceptedIndex);   // reference block at my tip index
    if (refBlock == nullptr || refBlock->blockHash != myTip->blockHash) { // my chain must be a prefix
        if (verbose) cout << "  Node's chain does not match reference (fork). Use 'Recover node'.\n"; // fork message
        return false;                                                // stop
    } // end if
    int added = 0;                                                   // count of copied blocks
    for (Block* cur = refBlock->next; cur != nullptr; cur = cur->next) { // each missing block
        string reason;                                               // error text
        n->chain.append(*cur);                                       // copy block to my chain
        if (!applyBlock(*cur, n->balances, reason)) {                // update my balances
            if (verbose) cout << "  Sync failed: " << reason << "\n"; // report problem
            return false;                                            // stop
        } // end if
        n->latestAcceptedIndex = cur->index;                         // update my tip index
        added++;                                                     // count it
    } // end for
    if (verbose) cout << "  Node " << n->userID << " synchronized. Blocks added: " << added  // final message
                      << ". New tip index: " << n->latestAcceptedIndex << ".\n";          // new tip
    logEvent("Node " + to_string(n->userID) + " synchronized, blocks added: " + to_string(added)); // record event
    return true;                                                     // success
} // end of syncNode

// Add a user and create its node
void addUser(int id, const string& name) {                           // id and display name
    User u;                                                          // new user record
    u.userID = id;                                                   // set ID
    u.displayName = name;                                            // set name
    u.accountID = 1000 + id;                                         // account number from ID
    u.activeStatus = true;                                           // new nodes start active
    users.insert(u);                                                 // put user in the BST
    for (size_t i = 0; i < nodes.size(); i++)                        // every existing node
        nodes[i]->balances.insert(u.accountID, START_BALANCE);       // gets the new account
    Node* n = createNode(id);                                        // create the new user's node
    syncNode(n, false);                                              // copy existing blocks quietly
    logEvent("User " + to_string(id) + " (" + name + ") registered"); // record event
} // end of addUser

// Erase everything and start again with users A, B, C
void resetSimulation() {                                             // used at start, by reset and demos
    for (size_t i = 0; i < nodes.size(); i++) delete nodes[i];       // free every node
    nodes.clear();                                                   // empty node list
    users.clear();                                                   // empty the BST
    pendingQueue.clear();                                            // empty the queue
    nextTxID = 1;                                                    // restart transaction IDs
    difficulty = 2;                                                  // default difficulty
    hasCandidate = false;                                            // no candidate block
    recoveryLog.clear();                                             // clear recovery events
    activityLog.clear();                                             // clear activity log
    addUser(1, "A");                                                 // sample user A
    addUser(2, "B");                                                 // sample user B
    addUser(3, "C");                                                 // sample user C
    logEvent("Simulation started/reset with users A, B, C");         // record event
} // end of resetSimulation

//==============================================================
//  PART 13 : CORE ACTIONS (used by menu and demos)
//==============================================================
// Change a node's active/inactive status
void setStatus(int id, bool active) {                                // id = user, active = new status
    User* u = users.search(id);                                      // find the user
    if (u == nullptr) return;                                        // unknown user: do nothing
    u->activeStatus = active;                                        // store new status
    logEvent("Node " + to_string(id) + " set to " + string(active ? "ACTIVE" : "INACTIVE")); // record event
} // end of setStatus

// Reject a transaction: print reason and log it
bool rejectTx(const string& head, const string& reason) {            // head = request text
    cout << "Rejected: " << reason << ".\n";                         // tell the user
    logEvent(head + " REJECTED (" + reason + ")");                   // record event
    return false;                                                    // always false
} // end of rejectTx

// Validate a transaction and put it in the queue
bool trySubmit(int sender, int receiver, int amount) {               // true = queued
    string head = "Tx request " + to_string(sender) + " -> " + to_string(receiver) + " amount " + to_string(amount); // text for log
    if (users.search(sender) == nullptr) return rejectTx(head, "sender is not registered");           // rule: unregistered sender
    if (users.search(receiver) == nullptr) return rejectTx(head, "receiver is not registered (unknown recipient)"); // rule: unknown receiver
    if (sender == receiver) return rejectTx(head, "self-transfer is not allowed");                    // rule: no self-transfer
    if (amount <= 0) return rejectTx(head, "amount must be greater than zero");                       // rule: positive amount
    Node* ref = findReferenceNode(nullptr);                          // valid node to read balances from
    if (ref == nullptr) return rejectTx(head, "no valid ledger available to check balance"); // no valid ledger
    HNode* bal = ref->balances.find(accountOf(sender));              // hash table lookup of sender
    int confirmed = (bal != nullptr) ? bal->balance : 0;             // confirmed balance
    int pending = pendingQueue.pendingOutgoing(sender);              // money already promised
    int spendable = confirmed - pending;                             // money still free to spend
    if (amount > spendable)                                          // rule: no overspending
        return rejectTx(head, "insufficient balance (confirmed " + to_string(confirmed) + ", pending " + to_string(pending) + ", spendable " + to_string(spendable) + ")"); // explain numbers
    Transaction t;                                                   // create the transaction
    t.transactionID = nextTxID++;                                    // give a unique ID
    t.senderID = sender;                                             // set sender
    t.receiverID = receiver;                                         // set receiver
    t.amount = amount;                                               // set amount
    t.timestamp = (long long)time(nullptr);                          // set creation time
    pendingQueue.enqueue(t);                                         // add at end of queue
    cout << "Accepted: Tx#" << t.transactionID << " (" << sender << " -> " << receiver << ", " << amount  // success message
         << ") added to pending queue (position " << pendingQueue.size() << "). Confirmed balance not changed yet.\n"; // note
    logEvent(head + " ACCEPTED as Tx#" + to_string(t.transactionID));// record event
    return true;                                                     // queued
} // end of trySubmit

// Search a nonce until the hash matches the difficulty
bool mineNonce(Block& b, int diff, long long& trials) {              // trials = number of hashes tried
    trials = 0;                                                      // start counting
    for (int nonce = 0; nonce < MAX_ATTEMPTS; nonce++) {             // try nonce values one by one
        b.nonce = nonce;                                             // set the nonce
        b.blockHash = calculateHash(b);                              // calculate the hash
        trials++;                                                    // count this try
        if (hasLeadingZeros(b.blockHash, diff)) return true;         // hash is good: done
    } // end for
    return false;                                                    // attempt limit reached (cancelled)
} // end of mineNonce

// Build and mine a candidate block
bool doMine(int minerID) {                                           // true = candidate ready
    if (hasCandidate) {                                              // a candidate already waits
        cout << "A candidate block already exists (conflicting candidate). Run the voting round first.\n"; // message
        return false;                                                // stop
    } // end if
    if (pendingQueue.isEmpty()) { cout << "Pending queue is empty. No block can be mined.\n"; return false; } // nothing to mine
    if (users.search(minerID) == nullptr) { cout << "Error: miner is not registered.\n"; return false; }     // unknown miner
    if (!isActive(minerID)) { cout << "Error: miner node is inactive.\n"; return false; }                    // inactive miner
    Node* ref = findReferenceNode(nullptr);                          // valid chain to build on
    if (ref == nullptr) { cout << "Error: no valid chain available to build on.\n"; return false; }          // none available
    Block* tip = ref->chain.getTail();                               // newest block
    Block b;                                                         // new candidate block
    b.index = tip->index + 1;                                        // next index
    b.previousHash = tip->blockHash;                                 // link to the tip
    b.txList = pendingQueue.firstN(MAX_TX_PER_BLOCK);                // copy first transactions (not removed yet)
    b.minerID = minerID;                                             // who mines
    b.difficulty = difficulty;                                       // current difficulty
    b.timestamp = (long long)time(nullptr);                          // creation time
    cout << "Mining block " << b.index << " with " << b.txList.size() << " transaction(s) at difficulty " << difficulty << "...\n"; // info
    long long trials;                                                // number of tries
    double t0 = nowMicros();                                         // start time
    bool found = mineNonce(b, difficulty, trials);                   // search the nonce
    double ms = (nowMicros() - t0) / 1000.0;                         // time used in milliseconds
    if (!found) {                                                    // limit reached
        cout << "Mining cancelled: attempt limit (" << MAX_ATTEMPTS << ") reached. Nothing was changed.\n"; // message
        logEvent("Mining cancelled at attempt limit");               // record event
        return false;                                                // stop
    } // end if
    candidate = b;                                                   // store the candidate
    candidate.next = nullptr;                                        // not linked to any chain yet
    hasCandidate = true;                                             // mark candidate as ready
    cout << "Mining successful!\n";                                  // success title
    cout << "  Nonce  : " << b.nonce << "\n";                        // show nonce
    cout << "  Hash   : " << b.blockHash << "\n";                    // show hash
    cout << "  Trials : " << trials << "\n";                         // show tries
    cout << "  Time   : " << fixed << setprecision(2) << ms << " ms\n"; // show time
    cout << "Candidate is ready. Run the voting round.\n";           // next step hint
    logEvent("Block " + to_string(b.index) + " mined by " + to_string(minerID) + " (nonce " + to_string(b.nonce) + ", trials " + to_string(trials) + ")"); // record event
    return true;                                                     // success
} // end of doMine

// Ask one node to vote on a block
bool nodeVote(Node* n, const Block& b, string& reason) {             // reason = why NO
    if (!validateChain(n, false)) { reason = "own chain is invalid"; return false; }                       // node must be healthy
    Block* tip = n->chain.getTail();                                 // node's newest block
    if (b.index != tip->index + 1) { reason = "sequence number does not match (node is outdated)"; return false; } // index check
    if (b.previousHash != tip->blockHash) { reason = "previous hash does not match node's tip"; return false; }    // link check
    if (calculateHash(b) != b.blockHash) { reason = "block hash is wrong"; return false; }                 // hash check
    if (b.difficulty != difficulty) { reason = "difficulty is not the required one"; return false; }       // difficulty check
    if (!hasLeadingZeros(b.blockHash, b.difficulty)) { reason = "hash does not meet difficulty"; return false; } // proof of work
    if (b.txList.empty()) { reason = "block has no transactions"; return false; }                          // empty block
    for (size_t i = 0; i < b.txList.size(); i++)                     // each new transaction
        for (Block* cur = n->chain.getHead(); cur != nullptr; cur = cur->next) // each old block
            for (size_t j = 0; j < cur->txList.size(); j++)          // each old transaction
                if (cur->txList[j].transactionID == b.txList[i].transactionID) { // same ID already in chain
                    reason = "transaction already exists in chain";  // set reason
                    return false;                                    // vote NO
                } // end if
    BalanceTable temp;                                               // temporary table
    temp.copyFrom(n->balances);                                      // copy node's balances
    string why;                                                      // error text
    if (!applyBlock(b, temp, why)) { reason = why; return false; }   // transfers must be valid
    return true;                                                     // vote YES
} // end of nodeVote

// Run the voting round for the candidate
bool runVoting() {                                                   // true = block approved
    if (!hasCandidate) { cout << "No candidate block. Mine a block first.\n"; return false; } // nothing to vote on
    vector<Transaction> front = pendingQueue.firstN((int)candidate.txList.size()); // first queue items
    bool same = (front.size() == candidate.txList.size());           // sizes must match
    for (size_t i = 0; same && i < front.size(); i++)                // compare item by item
        if (txToString(front[i]) != txToString(candidate.txList[i])) same = false; // content changed
    if (!same) {                                                     // candidate is outdated
        cout << "Candidate does not match the pending queue (transactions changed). Candidate discarded.\n"; // message
        logEvent("Candidate discarded: transactions changed");       // record event
        hasCandidate = false;                                        // remove candidate
        return false;                                                // stop
    } // end if
    vector<Node*> voters;                                            // snapshot of active nodes
    for (size_t i = 0; i < nodes.size(); i++)                        // check every node
        if (isActive(nodes[i]->userID)) voters.push_back(nodes[i]);  // keep active ones
    if (voters.empty()) { cout << "No active voters. Block cannot be approved.\n"; return false; } // nobody can vote
    cout << "Voting on block " << candidate.index << " (" << voters.size() << " eligible active node(s)):\n"; // heading
    vector<Node*> approvers;                                         // nodes that said YES
    for (size_t i = 0; i < voters.size(); i++) {                     // each voter
        string reason;                                               // reason for NO
        bool yes = nodeVote(voters[i], candidate, reason);           // ask the node
        User* u = users.search(voters[i]->userID);                   // for the name
        cout << "  Node " << voters[i]->userID << " (" << u->displayName << "): ";  // voter name
        if (yes) { cout << "YES\n"; approvers.push_back(voters[i]); voters[i]->votesYes++; } // count YES
        else { cout << "NO  - " << reason << "\n"; voters[i]->votesNo++; }                    // count NO
    } // end for
    int yesCount = (int)approvers.size();                            // number of YES votes
    int total = (int)voters.size();                                  // number of eligible voters
    cout << "Result: " << yesCount << " of " << total << " approved. "; // show result
    bool approved = (yesCount * 2 > total);                          // strict majority rule
    if (approved) {                                                  // block accepted
        cout << "MAJORITY REACHED -> block approved.\n";             // message
        for (size_t i = 0; i < approvers.size(); i++) {              // each approving node
            string reason;                                           // error text
            approvers[i]->chain.append(candidate);                   // add block to its chain
            applyBlock(candidate, approvers[i]->balances, reason);   // update its balances
            approvers[i]->latestAcceptedIndex = candidate.index;     // update its tip index
        } // end for
        Transaction removed;                                         // dummy variable
        for (size_t i = 0; i < candidate.txList.size(); i++) pendingQueue.dequeue(removed); // remove used transactions
        cout << "Block " << candidate.index << " added to " << approvers.size() << " node(s). Miner "  // result line
             << candidate.minerID << " received reward " << MINING_REWARD << ".\n";                    // reward note
        cout << "Other nodes (inactive or outdated) can be synchronized later.\n";                     // hint
        logEvent("Block " + to_string(candidate.index) + " APPROVED " + to_string(yesCount) + "/" + to_string(total)); // record event
    } else {                                                         // block rejected
        cout << "NOT ENOUGH VOTES -> block rejected. Chains, balances and queue are unchanged.\n";     // message
        logEvent("Block " + to_string(candidate.index) + " REJECTED " + to_string(yesCount) + "/" + to_string(total)); // record event
    } // end if-else
    hasCandidate = false;                                            // candidate is finished
    return approved;                                                 // tell the result
} // end of runVoting

// Change one block on a node (tamper demo)
bool doTamper(Node* n, int idx) {                                    // true = block was changed
    if (n == nullptr) return false;                                  // no node given
    Block* b = n->chain.getBlock(idx);                               // find the block
    if (idx < 1 || b == nullptr || b->txList.empty()) {              // must exist and be changeable
        cout << "Error: that block does not exist or cannot be changed.\n"; // message
        return false;                                                // stop
    } // end if
    b->txList[0].amount += 50;                                       // secretly change an amount
    cout << "DEMO: Block " << idx << " on node " << n->userID << " was changed (first transaction amount +50). Stored hash was NOT updated.\n"; // message
    logEvent("TAMPER demo: block " + to_string(idx) + " changed on node " + to_string(n->userID)); // record event
    return true;                                                     // changed
} // end of doTamper

// Restore a damaged node from a valid reference
bool doRecover(Node* n, bool askConfirm) {                           // askConfirm = ask user first?
    if (n == nullptr) return false;                                  // no node given
    if (validateChain(n, false)) {                                   // node is healthy
        cout << "Node " << n->userID << " is already valid. No recovery needed (use synchronize if outdated).\n"; // message
        return false;                                                // nothing to do
    } // end if
    validateChain(n, true);                                          // show what is wrong
    Node* ref = findReferenceNode(n);                                // best valid node (not itself)
    if (ref == nullptr) { cout << "Error: no fully valid reference node is available.\n"; return false; } // none found
    cout << "Reference node found: node " << ref->userID << " (tip index " << ref->latestAcceptedIndex << ").\n"; // info
    if (askConfirm && !readYesNo("Replace node " + to_string(n->userID) + "'s chain with the reference copy? (y/n): ")) { // explicit user action
        cout << "Recovery cancelled by user.\n";                     // message
        return false;                                                // stop
    } // end if
    n->chain.copyFrom(ref->chain);                                   // copy the valid chain
    n->latestAcceptedIndex = ref->latestAcceptedIndex;               // copy the tip index
    rebuildBalances(n);                                              // rebuild balances from history
    string event = "Recovery: node " + to_string(n->userID) + " restored from node " + to_string(ref->userID) + " at tip index " + to_string(n->latestAcceptedIndex); // event text
    recoveryLog.push_back(event);                                    // save in recovery log
    logEvent(event);                                                 // save in activity log
    cout << event << "\n";                                           // show it
    cout << "Check after recovery: " << (validateChain(n, false) ? "CHAIN VALID" : "STILL INVALID") << "\n"; // final check
    return true;                                                     // recovered
} // end of doRecover

//==============================================================
//  PART 14 : MENU ACTIONS (read input, then call core actions)
//==============================================================
// Menu 1: register a new user
void registerUser() {                                                // asks details and adds a user
    int id;                                                          // new user ID
    if (!readInt("Enter new user ID (positive number): ", id)) return;                       // read ID
    if (id <= 0) { cout << "Error: user ID must be positive.\n"; return; }                   // ID rule
    if (users.search(id) != nullptr) { cout << "Error: duplicate user ID. Registration rejected.\n"; return; } // duplicate rule
    string name = readLine("Enter display name: ");                  // read name
    if (name.empty()) { if (!inputEnded) cout << "Error: name cannot be empty.\n"; return; } // name rule
    addUser(id, name);                                               // create user and node
    cout << "User registered: ID " << id << ", Account " << 1000 + id << ", starting balance " << START_BALANCE  // success message
         << ". Node created and synchronized.\n";                    // note
} // end of registerUser

// Menu 2: search one user or list all users
void searchUsers() {                                                 // BST search / in-order traversal
    int id;                                                          // typed ID
    if (!readInt("Enter user ID to search (0 = list all users): ", id)) return; // read ID
    if (id == 0) {                                                   // 0 means list all
        cout << "Registered users (in-order traversal, " << users.size() << " total):\n"; // heading
        users.inOrder();                                             // sorted print
        return;                                                      // done
    } // end if
    User* u = users.search(id);                                      // BST search
    if (u == nullptr) { cout << "User " << id << " not found.\n"; return; } // not found
    cout << "Found -> ID: " << u->userID << " | Name: " << u->displayName << " | Account: " << u->accountID  // user info
         << " | Status: " << (u->activeStatus ? "ACTIVE" : "INACTIVE") << "\n";                             // status
} // end of searchUsers

// Menu 3: set a node active or inactive
void setNodeStatus() {                                               // asks ID and status
    int id, status;                                                  // typed values
    if (!readInt("Enter user/node ID: ", id)) return;                // read ID
    if (users.search(id) == nullptr) { cout << "Error: user not found.\n"; return; } // must exist
    if (!readInt("Enter status (1 = active, 0 = inactive): ", status)) return;       // read status
    if (status != 0 && status != 1) { cout << "Error: status must be 0 or 1.\n"; return; } // must be 0 or 1
    setStatus(id, status == 1);                                      // apply the change
    cout << "Node " << id << " is now " << (status == 1 ? "ACTIVE" : "INACTIVE") << ".\n"; // confirm
    if (status == 1) cout << "Tip: run 'Synchronize node' so it can update its copy.\n";   // hint
} // end of setNodeStatus

// Menu 4: show the blockchain of a node
void viewNodeChain() {                                               // linked list traversal
    Node* n = askNode("Enter node (user) ID: ");                     // choose node
    if (n == nullptr) return;                                        // invalid node
    cout << "Blockchain of node " << n->userID << " (" << n->chain.size() << " blocks):\n"; // heading
    for (Block* cur = n->chain.getHead(); cur != nullptr; cur = cur->next) { // walk from genesis
        printBlock(*cur, false);                                     // print block
        if (cur->next != nullptr) cout << "         |\n         v\n"; // arrow to next block
    } // end for
} // end of viewNodeChain

// Menu 5: submit a transaction
void submitTransaction() {                                           // asks sender, receiver, amount
    int sender, receiver, amount;                                    // typed values
    if (!readInt("Enter sender ID: ", sender)) return;               // read sender
    if (!readInt("Enter receiver ID: ", receiver)) return;           // read receiver
    if (!readInt("Enter amount (whole units): ", amount)) return;    // read amount
    trySubmit(sender, receiver, amount);                             // validate and queue
} // end of submitTransaction

// Menu 6: show the pending queue
void viewPending() {                                                 // queue traversal
    cout << "Pending transactions (" << pendingQueue.size() << "):\n"; // heading
    pendingQueue.display();                                          // print in arrival order
} // end of viewPending

// Menu 7: set mining difficulty
void setDifficulty() {                                               // asks new difficulty
    int d;                                                           // typed value
    cout << "Current difficulty: " << difficulty << " (allowed 1 to " << MAX_DIFFICULTY << ")\n"; // info
    if (!readInt("Enter new difficulty: ", d)) return;               // read value
    if (d < 1 || d > MAX_DIFFICULTY) { cout << "Error: difficulty not allowed.\n"; return; } // range rule
    difficulty = d;                                                  // store it
    cout << "Difficulty set to " << difficulty << ".\n";             // confirm
    logEvent("Difficulty set to " + to_string(difficulty));          // record event
    if (hasCandidate && candidate.difficulty != difficulty)          // pending candidate is now outdated
        cout << "Warning: the pending candidate uses difficulty " << candidate.difficulty << ", so voters will reject it.\n"; // warn
} // end of setDifficulty

// Menu 8: mine a candidate block
void mineBlock() {                                                   // asks the miner ID
    if (hasCandidate || pendingQueue.isEmpty()) { doMine(0); return; } // let doMine print the right message
    int minerID;                                                     // typed miner
    if (!readInt("Enter miner user ID: ", minerID)) return;          // read miner
    doMine(minerID);                                                 // mine the block
} // end of mineBlock

// Menu 10: check account balance
void checkBalance() {                                                // hash table lookup
    int uid;                                                         // typed user
    if (!readInt("Enter user ID to check (0 = all users): ", uid)) return; // read user
    if (uid != 0 && users.search(uid) == nullptr) { cout << "Error: user not found.\n"; return; } // must exist
    Node* n = askNode("Read balance from which node's copy? (node ID): "); // choose node
    if (n == nullptr) return;                                        // invalid node
    if (uid == 0) { printAllBalances(n); return; }                   // show every account
    HNode* e = n->balances.find(accountOf(uid));                     // hash table find
    if (e == nullptr) { cout << "Account not found in this node's table.\n"; return; } // missing entry
    int pending = pendingQueue.pendingOutgoing(uid);                 // waiting payments
    cout << "User " << uid << " (account " << e->accountID << ") on node " << n->userID << ":\n"; // heading
    cout << "  Confirmed balance : " << e->balance << "\n";          // confirmed money
    cout << "  Pending outgoing  : " << pending << "\n";             // pending money
    cout << "  Spendable         : " << e->balance - pending << "\n"; // free money
} // end of checkBalance

// Verify every node and print the result
void verifyAllNodes() {                                              // used by menu and demos
    for (size_t i = 0; i < nodes.size(); i++) {                      // each node
        bool ok = validateChain(nodes[i], true);                     // validate and print problems
        cout << "Node " << nodes[i]->userID << ": " << (ok ? "VALID" : "INVALID") << "\n"; // result
    } // end for
} // end of verifyAllNodes

// Menu 11: verify blockchain
void verifyChain() {                                                 // asks one or all
    cout << "Verify (1 = one node, 2 = all nodes): ";                // question
    int choice;                                                      // typed choice
    if (!readInt("", choice)) return;                                // read choice
    if (choice == 1) {                                               // one node
        Node* n = askNode("Enter node ID: ");                        // choose node
        if (n == nullptr) return;                                    // invalid node
        bool ok = validateChain(n, true);                            // validate
        cout << "Node " << n->userID << ": " << (ok ? "CHAIN VALID" : "CHAIN INVALID (tampering or error detected)") << "\n"; // result
    } else if (choice == 2) {                                        // all nodes
        verifyAllNodes();                                            // validate all
    } else {                                                         // anything else
        cout << "Invalid choice.\n";                                 // message
    } // end if-else
} // end of verifyChain

// Menu 12: tamper demonstration
void tamperDemo() {                                                  // asks node and block
    Node* n = askNode("Enter node ID to tamper: ");                  // choose node
    if (n == nullptr) return;                                        // invalid node
    int idx;                                                         // typed block index
    if (!readInt("Enter block index to change (1 or higher): ", idx)) return; // read index
    if (doTamper(n, idx)) cout << "Now run 'Verify blockchain' to detect it.\n"; // hint after success
} // end of tamperDemo

// Menu 13: synchronize one node
void syncMenu() {                                                    // asks node
    Node* n = askNode("Enter node ID to synchronize: ");             // choose node
    if (n == nullptr) return;                                        // invalid node
    if (!isActive(n->userID)) { cout << "Error: node is inactive. Activate it first.\n"; return; } // must be active
    Node* ref = findReferenceNode(nullptr);                          // best valid node
    if (ref != nullptr && ref != n) {                                // show comparison before syncing
        cout << "Comparison BEFORE synchronization:\n";              // heading
        printComparison(n, ref);                                     // side-by-side view
    } // end if
    syncNode(n, true);                                               // verify and update
} // end of syncMenu

// Menu 14: recover a node
void recoverMenu() {                                                 // asks node
    Node* n = askNode("Enter node ID to recover: ");                 // choose node
    doRecover(n, true);                                              // recover with confirmation
} // end of recoverMenu

// Menu 15: full confirmed history
void showHistory() {                                                 // all blocks and transactions
    Node* ref = findReferenceNode(nullptr);                          // valid node
    if (ref == nullptr) { cout << "No valid chain available.\n"; return; } // none available
    cout << "Confirmed history (from valid node " << ref->userID << "):\n"; // heading
    int totalTx = 0;                                                 // transaction counter
    for (Block* cur = ref->chain.getHead(); cur != nullptr; cur = cur->next) { // each block
        printBlock(*cur, true);                                      // print with full hashes
        totalTx += (int)cur->txList.size();                          // count transactions
    } // end for
    cout << "Total blocks: " << ref->chain.size() << " | Total confirmed transactions: " << totalTx << "\n"; // totals
} // end of showHistory

// Menu 16: node status, participation graph, recovery log
void showNodeStatus() {                                              // overview of all nodes
    cout << "Node status:\n";                                        // heading
    for (size_t i = 0; i < nodes.size(); i++) {                      // each node
        Node* n = nodes[i];                                          // current node
        User* u = users.search(n->userID);                           // its user
        cout << "  Node " << n->userID << " (" << u->displayName << ") | "              // id and name
             << (u->activeStatus ? "ACTIVE  " : "INACTIVE") << " | blocks: " << n->chain.size() // status and length
             << " | tip index: " << n->latestAcceptedIndex                              // tip index
             << " | tip hash: " << shortHash(n->chain.getTail()->blockHash)             // tip hash
             << " | " << (validateChain(n, false) ? "valid" : "INVALID") << "\n";       // validity
    } // end for
    cout << "Mining difficulty: " << difficulty << " | Pending transactions: " << pendingQueue.size() << "\n"; // settings
    cout << "Voting participation graph:\n";                         // graph heading
    for (size_t i = 0; i < nodes.size(); i++) {                      // each node
        User* u = users.search(nodes[i]->userID);                    // its user
        cout << "  Node " << nodes[i]->userID << " (" << u->displayName << ") YES " << pad(bar(nodes[i]->votesYes), 12) // YES bar
             << nodes[i]->votesYes << " | NO " << pad(bar(nodes[i]->votesNo), 12) << nodes[i]->votesNo << "\n";       // NO bar
    } // end for
    cout << "Recovery events (" << recoveryLog.size() << "):\n";     // recovery heading
    if (recoveryLog.empty()) cout << "  (none)\n";                   // no events
    for (size_t i = 0; i < recoveryLog.size(); i++) cout << "  - " << recoveryLog[i] << "\n"; // list events
} // end of showNodeStatus

// Menu 17: show the hash table of a node
void showHashTable() {                                               // shows buckets and collisions
    Node* n = askNode("Enter node ID: ");                            // choose node
    if (n == nullptr) return;                                        // invalid node
    cout << "Balance hash table of node " << n->userID << " (size " << HASH_SIZE << ", chaining):\n"; // heading
    n->balances.display();                                           // print buckets
} // end of showHashTable

// Menu 18: compare two nodes side by side
void compareMenu() {                                                 // asks two nodes
    Node* a = askNode("Enter first node ID: ");                      // first node
    if (a == nullptr) return;                                        // invalid node
    Node* b = askNode("Enter second node ID: ");                     // second node
    if (b == nullptr) return;                                        // invalid node
    printComparison(a, b);                                           // show comparison
} // end of compareMenu

// Menu 19: synchronize all active nodes
void syncAllMenu() {                                                 // update every active node
    for (size_t i = 0; i < nodes.size(); i++) {                      // each node
        if (!isActive(nodes[i]->userID)) {                           // inactive nodes are skipped
            cout << "  Node " << nodes[i]->userID << " is inactive: skipped.\n"; // message
            continue;                                                // next node
        } // end if
        syncNode(nodes[i], true);                                    // verify and update
    } // end for
} // end of syncAllMenu

// Menu 21: show the activity log
void viewActivityLog() {                                             // prints all saved events
    cout << "Activity log (" << activityLog.size() << " events):\n"; // heading
    for (size_t i = 0; i < activityLog.size(); i++)                  // each event
        cout << "  " << i + 1 << ". " << activityLog[i] << "\n";     // numbered line
} // end of viewActivityLog

// Menu 25: reset everything
void resetMenu() {                                                   // asks confirmation first
    if (!readYesNo("This erases all data and restarts with users A, B, C. Continue? (y/n): ")) { // confirm
        cout << "Reset cancelled.\n";                                // message
        return;                                                      // stop
    } // end if
    resetSimulation();                                               // erase and restart
    cout << "Simulation reset. Users A(1), B(2), C(3) created.\n";   // confirm
} // end of resetMenu

//==============================================================
//  PART 15 : EXPORT (CSV and text files)
//==============================================================
// Replace commas so CSV columns stay correct
string csvSafe(const string& s) {                                    // s = text to clean
    string r = s;                                                    // copy text
    for (size_t i = 0; i < r.size(); i++)                            // each character
        if (r[i] == ',') r[i] = ' ';                                 // comma becomes space
    return r;                                                        // cleaned text
} // end of csvSafe

// Menu 22: export users, blocks, transactions and log
void exportData() {                                                  // writes 4 files
    vector<User*> all;                                               // list of users
    users.collectUsers(all);                                         // get sorted users
    ofstream fu("users.csv");                                        // open users file
    if (!fu.is_open()) { cout << "Error: cannot create users.csv\n"; return; } // check file opened
    fu << "userID,displayName,accountID,status\n";                   // header line
    for (size_t i = 0; i < all.size(); i++)                          // each user
        fu << all[i]->userID << "," << csvSafe(all[i]->displayName) << "," << all[i]->accountID << ","  // columns 1-3
           << (all[i]->activeStatus ? "ACTIVE" : "INACTIVE") << "\n";                                   // column 4
    fu.close();                                                      // finish file
    cout << "Saved users.csv (" << all.size() << " users).\n";       // message
    Node* ref = findReferenceNode(nullptr);                          // valid chain to export
    if (ref == nullptr) {                                            // nothing valid
        cout << "No valid chain: blocks.csv and transactions.csv skipped.\n"; // message
    } else {                                                         // valid chain exists
        ofstream fb("blocks.csv");                                   // open blocks file
        ofstream ft("transactions.csv");                             // open transactions file
        if (!fb.is_open() || !ft.is_open()) { cout << "Error: cannot create block/transaction files.\n"; return; } // check files
        fb << "index,previousHash,minerID,nonce,difficulty,time,blockHash,txCount\n";           // blocks header
        ft << "blockIndex,transactionID,senderID,receiverID,amount,time\n";                     // transactions header
        int txCount = 0;                                             // counts transactions
        for (Block* cur = ref->chain.getHead(); cur != nullptr; cur = cur->next) {              // each block
            fb << cur->index << "," << cur->previousHash << "," << cur->minerID << "," << cur->nonce << "," // block columns 1-4
               << cur->difficulty << "," << timeToText(cur->timestamp) << "," << cur->blockHash << ","      // block columns 5-7
               << cur->txList.size() << "\n";                        // block column 8
            for (size_t i = 0; i < cur->txList.size(); i++) {        // each transaction
                const Transaction& t = cur->txList[i];               // short name
                ft << cur->index << "," << t.transactionID << "," << t.senderID << "," << t.receiverID << "," // columns 1-4
                   << t.amount << "," << timeToText(t.timestamp) << "\n";                                    // columns 5-6
                txCount++;                                           // count it
            } // end for
        } // end for
        fb.close();                                                  // finish blocks file
        ft.close();                                                  // finish transactions file
        cout << "Saved blocks.csv (" << ref->chain.size() << " blocks) and transactions.csv (" << txCount << " transactions).\n"; // message
    } // end if-else
    ofstream fl("activity_log.txt");                                 // open log file
    if (!fl.is_open()) { cout << "Error: cannot create activity_log.txt\n"; return; } // check file opened
    fl << "BLOCKCHAIN SIMULATION - ACTIVITY LOG\n";                  // title line
    for (size_t i = 0; i < activityLog.size(); i++) fl << i + 1 << ". " << activityLog[i] << "\n"; // each event
    fl.close();                                                      // finish file
    cout << "Saved activity_log.txt (" << activityLog.size() << " events).\n"; // message
    logEvent("Data exported to CSV/text files");                     // record event
} // end of exportData

//==============================================================
//  PART 16 : PREDEFINED DEMO SCENARIOS
//==============================================================
// Print a demo step heading
void demoStep(const string& text) {                                  // text = step title
    cout << "\n>>> " << text << "\n";                                // print heading
} // end of demoStep

// Demo 1: normal flow from registration to approved block
void demoNormalFlow() {                                              // proposal use-case walkthrough
    resetSimulation();                                               // fresh start
    demoStep("Step 1: nodes A, B, C exist with the same genesis block."); // step title
    showNodeStatus();                                                // show nodes
    demoStep("Step 2: register a fourth user D.");                   // step title
    addUser(4, "D");                                                 // add user D
    cout << "User D registered (ID 4).\n";                           // message
    demoStep("Step 3: submit sample transactions.");                 // step title
    trySubmit(1, 2, 30);                                             // valid transfer
    trySubmit(2, 3, 20);                                             // valid transfer
    trySubmit(3, 4, 10);                                             // valid transfer
    viewPending();                                                   // show queue
    demoStep("Step 4: mine a block (miner = node 1).");              // step title
    doMine(1);                                                       // mine
    demoStep("Step 5: voting round.");                               // step title
    runVoting();                                                     // vote
    demoStep("Step 6: balances after the approved block.");          // step title
    printAllBalances(findNode(1));                                   // show balances
    demoStep("Step 7: pending queue after commit (should be empty)."); // step title
    viewPending();                                                   // show queue
} // end of demoNormalFlow

// Demo 2: rejected transactions and empty-queue mining
void demoRejected() {                                                // tests T03, T04, T09
    resetSimulation();                                               // fresh start
    demoStep("T04: mine with an empty queue.");                      // step title
    doMine(1);                                                       // must fail
    demoStep("T03: invalid transactions (all must be rejected).");   // step title
    trySubmit(99, 1, 10);                                            // unregistered sender
    trySubmit(1, 99, 10);                                            // unknown recipient
    trySubmit(1, 1, 10);                                             // self-transfer
    trySubmit(1, 2, 0);                                              // zero amount
    trySubmit(1, 2, -5);                                             // negative amount
    trySubmit(1, 2, 500);                                            // amount too high
    demoStep("T09: repeated payments from the same sender (balance 100)."); // step title
    trySubmit(1, 2, 80);                                             // accepted
    trySubmit(1, 3, 30);                                             // rejected: pending 80 + 30 > 100
    trySubmit(1, 3, 20);                                             // accepted: exactly 100 in total
    viewPending();                                                   // show queue
} // end of demoRejected

// Demo 3: inactive node and synchronization
void demoInactiveSync() {                                            // tests T06 and sync
    resetSimulation();                                               // fresh start
    demoStep("Step 1: block 1 with all nodes active.");              // step title
    trySubmit(1, 2, 10);                                             // transaction
    doMine(1);                                                       // mine
    runVoting();                                                     // vote
    demoStep("Step 2: node 3 becomes inactive.");                    // step title
    setStatus(3, false);                                             // deactivate node 3
    demoStep("Step 3: block 2 while node 3 is inactive.");           // step title
    trySubmit(2, 1, 5);                                              // transaction
    doMine(2);                                                       // mine
    runVoting();                                                     // vote (node 3 is skipped)
    demoStep("Step 4: node 3 is now behind.");                       // step title
    showNodeStatus();                                                // show status
    demoStep("Step 5: reactivate node 3 and compare it with node 1."); // step title
    setStatus(3, true);                                              // reactivate
    printComparison(findNode(3), findNode(1));                       // side-by-side view
    demoStep("Step 6: synchronize node 3.");                         // step title
    syncNode(findNode(3), true);                                     // verify and update
    showNodeStatus();                                                // show final status
} // end of demoInactiveSync

// Demo 4: tampering and recovery
void demoTamperRecover() {                                           // tests T07 and T08
    resetSimulation();                                               // fresh start
    demoStep("Step 1: create block 1.");                             // step title
    trySubmit(1, 2, 25);                                             // transaction
    doMine(1);                                                       // mine
    runVoting();                                                     // vote
    demoStep("Step 2: tamper block 1 on node 2.");                   // step title
    doTamper(findNode(2), 1);                                        // change the block
    demoStep("Step 3: verify all nodes (node 2 must fail).");        // step title
    verifyAllNodes();                                                // validate all
    demoStep("Step 4: recover node 2 from a valid node.");           // step title
    doRecover(findNode(2), false);                                   // recover without asking
    demoStep("Step 5: verify all nodes again (all must be valid).");  // step title
    verifyAllNodes();                                                // validate all
} // end of demoTamperRecover

// Demo 5: voting fails because only 2 of 4 nodes approve
void demoFailedVote() {                                              // tests T05
    resetSimulation();                                               // fresh start
    addUser(4, "D");                                                 // four nodes in total
    demoStep("Step 1: block 1 approved by all 4 nodes.");            // step title
    trySubmit(1, 2, 10);                                             // transaction
    doMine(1);                                                       // mine
    runVoting();                                                     // vote
    demoStep("Step 2: tamper nodes 3 and 4 (2 of 4 nodes become bad)."); // step title
    doTamper(findNode(3), 1);                                        // damage node 3
    doTamper(findNode(4), 1);                                        // damage node 4
    demoStep("Step 3: new block: only 2 of 4 approve (not a majority)."); // step title
    trySubmit(2, 1, 5);                                              // transaction
    doMine(1);                                                       // mine
    runVoting();                                                     // vote fails
    demoStep("Step 4: the transaction is still pending (not lost).");// step title
    viewPending();                                                   // show queue
    demoStep("Step 5: recover nodes 3 and 4.");                      // step title
    doRecover(findNode(3), false);                                   // recover node 3
    doRecover(findNode(4), false);                                   // recover node 4
    demoStep("Step 6: vote the same transaction again (should pass)."); // step title
    doMine(1);                                                       // mine again
    runVoting();                                                     // vote passes
} // end of demoFailedVote

// Menu 20: choose a demo scenario
void demoMenu() {                                                    // asks which demo
    cout << "Demo scenarios (each one RESETS the simulation first):\n"; // heading
    cout << "  1. Normal flow (register, queue, mine, vote)\n";      // option 1
    cout << "  2. Rejected transactions (T03, T04, T09)\n";          // option 2
    cout << "  3. Inactive node and synchronization (T06)\n";        // option 3
    cout << "  4. Tamper detection and recovery (T07, T08)\n";       // option 4
    cout << "  5. Failed vote: 2 of 4 approvals (T05)\n";            // option 5
    int c;                                                           // typed choice
    if (!readInt("Choose scenario (0 = cancel): ", c)) return;       // read choice
    if (c == 0) return;                                              // cancel
    if (c < 1 || c > 5) { cout << "Invalid scenario number.\n"; return; } // range check
    if (!readYesNo("This will erase current data. Continue? (y/n): ")) { cout << "Demo cancelled.\n"; return; } // confirm
    switch (c) {                                                     // run the chosen demo
        case 1: demoNormalFlow(); break;                             // demo 1
        case 2: demoRejected(); break;                               // demo 2
        case 3: demoInactiveSync(); break;                           // demo 3
        case 4: demoTamperRecover(); break;                          // demo 4
        case 5: demoFailedVote(); break;                             // demo 5
    } // end switch
    cout << "\nDemo finished. The simulation stays in the final demo state (menu 25 resets it).\n"; // note
} // end of demoMenu

//==============================================================
//  PART 17 : SELF TESTS
//==============================================================
int testsPassed = 0;                   // number of passed checks
int testsFailed = 0;                   // number of failed checks

// Record one test result
void check(bool condition, const string& name) {                     // name = test description
    if (condition) { testsPassed++; cout << "  [PASS] " << name << "\n"; } // passed
    else { testsFailed++; cout << "  [FAIL] " << name << "\n"; }          // failed
} // end of check

// Menu 23: test the core data structures
void runSelfTests() {                                                // does not touch simulation data
    testsPassed = 0;                                                 // reset counter
    testsFailed = 0;                                                 // reset counter
    cout << "Running self tests...\n";                               // heading

    check(sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 of 'abc'");   // known hash 1
    check(sha256("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 of empty text"); // known hash 2

    UserBST t;                                                       // temporary tree
    User a{50, "A", 1050, true}, b{20, "B", 1020, true}, c{70, "C", 1070, true}; // test users
    check(t.insert(a) && t.insert(b) && t.insert(c), "BST insert 3 users"); // insert test
    check(!t.insert(a), "BST rejects duplicate ID");                 // duplicate test
    check(t.search(20) != nullptr && t.search(99) == nullptr, "BST search found / not found"); // search test
    vector<User*> list;                                              // sorted list
    t.collectUsers(list);                                            // in-order traversal
    check(list.size() == 3 && list[0]->userID == 20 && list[1]->userID == 50 && list[2]->userID == 70, "BST in-order is sorted"); // order test

    TxQueue q;                                                       // temporary queue
    Transaction t1{1, 1, 2, 10, 0}, t2{2, 2, 3, 20, 0}, t3{3, 1, 3, 5, 0}, out; // test transactions
    check(q.isEmpty(), "Queue starts empty");                        // empty test
    q.enqueue(t1); q.enqueue(t2); q.enqueue(t3);                     // add three items
    check(q.size() == 3, "Queue size after 3 enqueue");              // size test
    check(q.peek(out) && out.transactionID == 1 && q.size() == 3, "Queue peek does not remove"); // peek test
    check(q.pendingOutgoing(1) == 15, "Queue pending outgoing of sender 1"); // pending test
    check(q.firstN(2).size() == 2 && q.size() == 3, "Queue firstN does not remove"); // firstN test
    check(q.dequeue(out) && out.transactionID == 1, "Queue dequeue gives first item"); // FIFO test 1
    check(q.dequeue(out) && out.transactionID == 2, "Queue keeps FIFO order");         // FIFO test 2
    q.dequeue(out);                                                  // remove last item
    check(!q.dequeue(out), "Queue dequeue on empty returns false");  // empty dequeue test

    BalanceTable h;                                                  // temporary hash table
    h.insert(5, 100);                                                // key 5 goes to bucket 5
    h.insert(16, 200);                                               // key 16 also goes to bucket 5 (collision)
    check(h.find(5) != nullptr && h.find(5)->balance == 100, "Hash table finds key 5");          // find test 1
    check(h.find(16) != nullptr && h.find(16)->balance == 200, "Hash table handles collision");  // collision test
    check(h.update(5, 150) && h.find(5)->balance == 150, "Hash table update");                   // update test
    check(!h.update(999, 1) && h.find(999) == nullptr, "Hash table missing key");                // missing test
    BalanceTable h2;                                                 // second table
    h2.copyFrom(h);                                                  // copy test
    check(h2.find(16) != nullptr && h2.find(16)->balance == 200, "Hash table copyFrom");         // copy result

    Block g = makeGenesis();                                         // genesis block
    check(calculateHash(g) == g.blockHash, "Genesis hash is consistent"); // genesis test
    Block m;                                                         // test block
    m.index = 1; m.previousHash = g.blockHash; m.minerID = 1; m.difficulty = 1; m.timestamp = 1; // fill fields
    long long trials;                                                // tries counter
    check(mineNonce(m, 1, trials) && hasLeadingZeros(m.blockHash, 1), "Mining finds a valid hash"); // mining test
    string reason;                                                   // error text
    check(checkBlockLinks(m, g, reason), "Valid block passes link check"); // valid block test
    m.minerID = 2;                                                   // change block data
    check(!checkBlockLinks(m, g, reason), "Changed block is detected");    // tamper test

    Chain c1, c2;                                                    // two temporary chains
    c1.append(g); c1.append(m);                                      // two blocks in chain 1
    c2.copyFrom(c1);                                                 // deep copy
    check(c2.size() == 2 && c2.getBlock(1) != nullptr && c2.getBlock(1) != c1.getBlock(1), "Chain copy is a deep copy"); // copy test

    cout << "Result: " << testsPassed << " passed, " << testsFailed << " failed.\n"; // summary
} // end of runSelfTests

//==============================================================
//  PART 18 : PERFORMANCE TEST
//==============================================================
volatile int sink = 0;                 // stops the compiler from deleting test loops

// Menu 24: measure running times
void performanceTest() {                                             // does not touch simulation data
    int sizes[3] = {10, 50, 100};                                    // user counts to test
    const int REPS = 1000;                                           // repeat count for stable times
    cout << "Performance test (average time per operation)\n";       // heading
    cout << fixed << setprecision(1);                                // one decimal place
    cout << setw(7) << "Size" << setw(14) << "BST ins(ns)" << setw(14) << "BST find(ns)" << setw(14) << "Hash find(ns)" // column titles 1
         << setw(14) << "Queue op(ns)" << setw(18) << "Verify chain(us)" << "\n";                                      // column titles 2
    for (int s = 0; s < 3; s++) {                                    // each size
        int n = sizes[s];                                            // current size
        vector<int> ids;                                             // unique test IDs
        for (int i = 0; i < n; i++) ids.push_back((i * 7919) % 100003 + 1); // spread-out unique IDs
        UserBST bst;                                                 // test tree
        double t0 = nowMicros();                                     // start timer
        for (int i = 0; i < n; i++) { User u{ids[i], "U", 1000 + ids[i], true}; bst.insert(u); } // insert all
        double bstInsert = (nowMicros() - t0) * 1000.0 / n;          // ns per insert
        int found = 0;                                               // counts found items
        t0 = nowMicros();                                            // start timer
        for (int r = 0; r < REPS; r++)                               // repeat many times
            for (int i = 0; i < n; i++) if (bst.search(ids[i]) != nullptr) found++; // search all
        double bstFind = (nowMicros() - t0) * 1000.0 / ((double)REPS * n); // ns per search
        BalanceTable table;                                          // test hash table
        for (int i = 0; i < n; i++) table.insert(1000 + ids[i], START_BALANCE); // insert all
        t0 = nowMicros();                                            // start timer
        for (int r = 0; r < REPS; r++)                               // repeat many times
            for (int i = 0; i < n; i++) if (table.find(1000 + ids[i]) != nullptr) found++; // find all
        double hashFind = (nowMicros() - t0) * 1000.0 / ((double)REPS * n); // ns per lookup
        TxQueue q;                                                   // test queue
        Transaction tx{1, 1, 2, 5, 0}, out;                          // test transaction
        t0 = nowMicros();                                            // start timer
        for (int r = 0; r < REPS; r++) {                             // repeat many times
            for (int i = 0; i < n; i++) q.enqueue(tx);               // add n items
            for (int i = 0; i < n; i++) q.dequeue(out);              // remove n items
        } // end for
        double queueOp = (nowMicros() - t0) * 1000.0 / ((double)REPS * 2 * n); // ns per operation
        Chain chain;                                                 // test chain
        chain.append(makeGenesis());                                 // add genesis
        for (int i = 0; i < n; i++) {                                // build n blocks
            Block b;                                                 // new block
            Block* tip = chain.getTail();                            // current newest block
            b.index = tip->index + 1; b.previousHash = tip->blockHash; // index and link
            b.minerID = 1; b.difficulty = 1; b.timestamp = 1;        // other fields
            long long tr;                                            // tries counter
            mineNonce(b, 1, tr);                                     // mine at difficulty 1
            chain.append(b);                                         // add to chain
        } // end for
        t0 = nowMicros();                                            // start timer
        for (int r = 0; r < 100; r++) {                              // repeat 100 times
            string reason;                                           // error text
            Block* prev = chain.getHead();                           // start at genesis
            for (Block* cur = prev->next; cur != nullptr; cur = cur->next) { // each block
                checkBlockLinks(*cur, *prev, reason);                // verify it
                prev = cur;                                          // move forward
            } // end for
        } // end for
        double verifyTime = (nowMicros() - t0) / 100.0;              // microseconds per full verification
        sink = sink + found;                                         // use the result so loops stay
        cout << setw(7) << n << setw(14) << bstInsert << setw(14) << bstFind << setw(14) << hashFind // print row part 1
             << setw(14) << queueOp << setw(18) << verifyTime << "\n";                              // print row part 2
    } // end for (sizes)

    cout << "\nMining attempts per difficulty (average of 5 blocks, log-scale graph):\n"; // graph heading
    for (int d = 1; d <= MAX_DIFFICULTY; d++) {                      // each difficulty
        long long totalTrials = 0;                                   // sum of tries
        double t0 = nowMicros();                                     // start timer
        for (int k = 0; k < 5; k++) {                                // 5 sample blocks
            Block b;                                                 // sample block
            b.index = 1; b.previousHash = "0"; b.minerID = 1; b.difficulty = d; b.timestamp = 100 + k; // different data each time
            long long trials;                                        // tries counter
            mineNonce(b, d, trials);                                 // mine it
            totalTrials += trials;                                   // add to the sum
        } // end for
        double ms = (nowMicros() - t0) / 1000.0 / 5.0;               // average milliseconds
        long long avg = totalTrials / 5;                             // average tries
        int len = (int)(log10((double)avg + 1.0) * 8.0);             // bar length (log scale)
        cout << "  Difficulty " << d << " | " << pad(bar(len), 40) << " " << avg << " trials, " // bar and tries
             << setprecision(2) << ms << " ms\n";                    // average time
    } // end for (difficulties)
    cout << "(Times depend on your computer. Higher difficulty needs many more attempts.)\n"; // note
} // end of performanceTest

//==============================================================
//  PART 19 : MAIN MENU
//==============================================================
// Print the menu
void showMenu() {                                                    // shows all options
    cout << "\n==================== BLOCKCHAIN SIMULATION ====================\n";  // top line
    cout << " 1. Register user               2. Search / list users\n";           // options 1-2
    cout << " 3. Set node active/inactive    4. View node's blockchain\n";        // options 3-4
    cout << " 5. Submit transaction          6. View pending queue\n";            // options 5-6
    cout << " 7. Set mining difficulty       8. Mine candidate block\n";          // options 7-8
    cout << " 9. Voting round               10. Check account balance\n";         // options 9-10
    cout << "11. Verify blockchain          12. Tamper demonstration\n";          // options 11-12
    cout << "13. Synchronize node           14. Recover node\n";                  // options 13-14
    cout << "15. Transaction & block history 16. Node status & vote graph\n";     // options 15-16
    cout << "17. Show balance hash table    18. Compare two nodes (side by side)\n"; // options 17-18
    cout << "19. Synchronize ALL active nodes 20. Run demo scenario\n";           // options 19-20
    cout << "21. View activity log          22. Export data (CSV / text)\n";     // options 21-22
    cout << "23. Run self tests             24. Run performance test\n";         // options 23-24
    cout << "25. Reset simulation\n";                                             // option 25
    cout << " 0. Exit\n";                                                         // exit option
    cout << "================================================================\n";// bottom line
} // end of showMenu

// Free all node memory
void cleanup() {                                                     // called before the program ends
    for (size_t i = 0; i < nodes.size(); i++) delete nodes[i];       // free each node
    nodes.clear();                                                   // empty the list
} // end of cleanup

// Program starts here
int main() {                                                         // entry point
    resetSimulation();                                               // create users A, B, C and genesis
    cout << "Blockchain Simulation started.\n";                      // welcome line 1
    cout << "Genesis block created. Test nodes A(1), B(2), C(3) created, each with balance " << START_BALANCE << ".\n"; // welcome line 2
    cout << "Rules: block size = " << MAX_TX_PER_BLOCK << " tx, mining reward = " << MINING_REWARD  // welcome line 3
         << ", default difficulty = " << difficulty << ".\n";        // welcome line 3 (end)
    while (!inputEnded) {                                            // repeat until input ends or user exits
        showMenu();                                                  // show options
        int choice;                                                  // typed option
        if (!readInt("Enter choice: ", choice)) continue;            // invalid number: show menu again
        cout << "\n";                                                // blank line for readability
        switch (choice) {                                            // run the chosen action
            case 1:  registerUser();       break;                    // register user
            case 2:  searchUsers();        break;                    // search / list users
            case 3:  setNodeStatus();      break;                    // set status
            case 4:  viewNodeChain();      break;                    // view chain
            case 5:  submitTransaction();  break;                    // submit transaction
            case 6:  viewPending();        break;                    // view queue
            case 7:  setDifficulty();      break;                    // set difficulty
            case 8:  mineBlock();          break;                    // mine block
            case 9:  runVoting();          break;                    // voting round
            case 10: checkBalance();       break;                    // check balance
            case 11: verifyChain();        break;                    // verify chain
            case 12: tamperDemo();         break;                    // tamper demo
            case 13: syncMenu();           break;                    // synchronize node
            case 14: recoverMenu();        break;                    // recover node
            case 15: showHistory();        break;                    // history
            case 16: showNodeStatus();     break;                    // node status and graph
            case 17: showHashTable();      break;                    // hash table view
            case 18: compareMenu();        break;                    // compare nodes
            case 19: syncAllMenu();        break;                    // synchronize all
            case 20: demoMenu();           break;                    // demo scenarios
            case 21: viewActivityLog();    break;                    // activity log
            case 22: exportData();         break;                    // export files
            case 23: runSelfTests();       break;                    // self tests
            case 24: performanceTest();    break;                    // performance test
            case 25: resetMenu();          break;                    // reset
            case 0:                                                  // exit
                cout << "Goodbye!\n";                                // farewell
                cleanup();                                           // free memory
                return 0;                                            // end program
            default:                                                 // any other number
                cout << "Invalid menu choice. Please enter a number from 0 to 25.\n"; // error message
        } // end switch
    } // end while
    cleanup();                                                       // free memory when input ends
    return 0;                                                        // end program
} // end of main
