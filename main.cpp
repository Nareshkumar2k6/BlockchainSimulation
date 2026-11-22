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
//      - hasLeadingZeros()
//
// 2. Implement and maintain blockchain data structures:
//      - Chain class
//      - append()
//      - getBlock()
//      - getHead()
//      - getTail()
//
// 3. Implement and maintain block operations:
//      - mineNonce()
//      - doMine()
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
//      - submitTransaction()
//      - viewPending()
//      - processTransactions()
//
// 3. Implement and improve account balance management:
//      - BalanceTable class
//      - insert()
//      - search()
//      - update()
//      - printAllBalances()
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
//      - vote handling functions
//      - majority approval validation
//      - rejected block handling
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

