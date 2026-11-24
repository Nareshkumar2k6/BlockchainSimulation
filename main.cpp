#include <iostream>
#include <cstdint>    // uint32_t, uint64_t: fixed-size integers for SHA-256
using namespace std;


MEMBER 1: NARESH KUMAR (PROJECT LEADER)
// RESPONSIBILITIES:
// 1. Implement and maintain SHA-256 hashing functions:
  static const uint32_t K[64] = {                                                              // 64 fixed SHA-256 round constants (never change a digit)
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5, // constants for rounds 0-7
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174, // constants for rounds 8-15
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da, // constants for rounds 16-23
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967, // constants for rounds 24-31
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85, // constants for rounds 32-39
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070, // constants for rounds 40-47
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3, // constants for rounds 48-55
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2  // constants for rounds 56-63
};
//      - rotr()
  // Rotate bits of x to the right
uint32_t rotr(uint32_t x, int n) {                                   // x = number, n = how many bits to rotate
    return (x >> n) | (x << (32 - n));                               // shift right, and wrap lost bits to the left
}
//      - sha256()
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
}
//      - calculateHash()
string calculateHash(const Block& b) {                               // block -> hash
    return sha256(blockToString(b));                                 // hash the block text
} // end of calculateHash
//      - hasLeadingZeros()
bool hasLeadingZeros(const string& hash, int d) {                    // d = required zeros
    for (int i = 0; i < d; i++)                                      // check first d characters
        if (hash[i] != '0') return false;                            // any non-zero means failure
    return true;                                                     // all were zeros
} // end of hasLeadingZeros
//
// 2. Implement and maintain blockchain data structures:
//      - Chain class
//      - append()
//      - getBlock()
//      - getHead()
//      - getTail()
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
//
// 3. Implement and maintain block operations:
//      - mineNonce()
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


//      - doMine()
// Build and mine a candidate block
bool doMine(int minerID) {                                           // true = candidate ready
    if (hasCandidate) {                                              // a candidate already waits
        cout << "A candidate block already exists (conflicting candidate). Run the voting round first.\n"; // message
        return false;                                                // stop
    }
//      - verifyChain()
//      - validateBlock()
//
// 4. Integrate all members' code into the main project.
// 5. Review and merge pull requests.
// 6. Test the complete blockchain simulation.
//
//--------------------------------------------------------------
//
MEMBER 2: JANMESH KUMAR
// RESPONSIBILITIES:
// 1. Implement and improve transaction management:
//      - TxQueue class
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


//      - enqueue()
void enqueue(const Transaction& t) {                             // t = new transaction
        QNode* n = new QNode{t, nullptr};                            // create the node
        if (rear == nullptr) front = n;                              // first item: it is also the front
        else rear->next = n;                                         // otherwise link after the old rear
        rear = n;                                                    // new node is now the rear
        count++;                                                     // one more item
    } // end of enqueue

//      - dequeue()
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

//      - peek()
  // Look at the first transaction (no removal)
    bool peek(Transaction& out) {                                    // out receives a copy
        if (front == nullptr) return false;                          // queue is empty
        out = front->data;                                           // copy the first item
        return true;                                                 // success
    } // end of peek

//      - firstN()
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

//      - pendingOutgoing()
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

//
// 2. Implement and improve transaction operations:
//      - trySubmit()
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

//      - submitTransaction()
void submitTransaction() {                                           // asks sender, receiver, amount
    int sender, receiver, amount;                                    // typed values
    if (!readInt("Enter sender ID: ", sender)) return;               // read sender
    if (!readInt("Enter receiver ID: ", receiver)) return;           // read receiver
    if (!readInt("Enter amount (whole units): ", amount)) return;    // read amount
    trySubmit(sender, receiver, amount);                             // validate and queue
} // end of submitTransaction


//      - viewPending()
void viewPending() {                                                 // queue traversal
    cout << "Pending transactions (" << pendingQueue.size() << "):\n"; // heading
    pendingQueue.display();                                          // print in arrival order
} // end of viewPending


//      - processTransactions()

//
// 3. Implement and improve account balance management:
//      - BalanceTable class
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


//      - insert()
void insert(int accountID, int balance) {                        // key and value
        HNode* existing = find(accountID);                           // already stored?
        if (existing != nullptr) { existing->balance = balance; return; } // yes: just update value
        int i = hashFunction(accountID);                             // choose the bucket
        buckets[i] = new HNode{accountID, balance, buckets[i]};      // add new entry at the chain head (handles collisions)
    } // end of insert


//      - search()
 User* search(int id) {                                           // returns nullptr if not found
        BSTNode* cur = root;                                         // start at the top
        while (cur != nullptr) {                                     // walk down the tree
            if (id == cur->data.userID) return &cur->data;           // found the user
            if (id < cur->data.userID) cur = cur->left;              // smaller: go left
            else cur = cur->right;                                   // bigger: go right
        } // end while
        return nullptr;                                              // not in the tree
    } // end of search

//      - update()
 bool update(int accountID, int newBalance) {                     // returns false if missing
        HNode* e = find(accountID);                                  // look for the entry
        if (e == nullptr) return false;                              // not found
        e->balance = newBalance;                                     // store new balance
        return true;                                                 // success
    } // end of update
//      - printAllBalances()
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


//
// 4. Handle transaction validation:
//      - Check sender and receiver IDs.
//      - Check transaction amounts.
//      - Prevent insufficient-balance transactions.
//      - Prevent double spending.
//
// 5. Add and maintain transaction-related test cases.
//
//--------------------------------------------------------------
//
MEMBER 3: ABDUL SAMAD
// RESPONSIBILITIES:
// 1. Implement and improve node management:
//      - findNode()
// Find a node by user ID
Node* findNode(int userID) {                                         // returns nullptr if missing
    for (size_t i = 0; i < nodes.size(); i++)                        // check every node
        if (nodes[i]->userID == userID) return nodes[i];             // found it
    return nullptr;                                                  // no such node
} // end of findNode

//      - findReferenceNode()
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

//      - isActive()
// Check if a user's node is active
bool isActive(int userID) {                                          // true = active
    User* u = users.search(userID);                                  // BST search
    return (u != nullptr && u->activeStatus);                        // must exist and be active
} // end of isActive

//      - setNodeStatus()
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
//
// 2. Implement and improve consensus and voting:
//      - runVoting()
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
//      - vote handling functions
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
//      - majority approval validation
    bool approved = (yesCount * 2 > total);                          // strict majority rule
//      - rejected block handling
    } else {                                                         // block rejected
        cout << "NOT ENOUGH VOTES -> block rejected. Chains, balances and queue are unchanged.\n";     // message
        logEvent("Block " + to_string(candidate.index) + " REJECTED " + to_string(yesCount) + "/" + to_string(total)); // record event
    } // end if-else
    if (voters.empty()) { cout << "No active voters. Block cannot be approved.\n"; return false; } // nobody can vote
//
// 3. Implement and improve blockchain synchronization:
//      - doSync()
//      - synchronizeAll()
//      - doRecover()
//
// 4. Implement and improve node monitoring:
//      - showNodeStatus()
//      - viewNodeChain()
//      - compareNodes()
//      - display vote results
//
// 5. Add and maintain consensus, synchronization,
//    and node-recovery test cases.
//

