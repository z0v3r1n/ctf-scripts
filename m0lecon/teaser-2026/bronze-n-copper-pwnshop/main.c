using namespace std;
#include <cstring>
#include <forward_list>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

typedef unsigned long tag_t;

struct Memory {
    int64_t timestamp;
    char description[0x10];
    mutable vector<tag_t> tags;

    Memory(int64_t ts) : timestamp(ts), description{} {}
    Memory(int64_t ts, const char *desc) : timestamp(ts), description{} {
        if (desc) {
            strncpy(this->description, desc, sizeof(description) - 1);
            this->description[sizeof(description) - 1] = '\0';
        }
    }

    bool operator==(const Memory &o) const { return timestamp == o.timestamp; }
    bool operator<(const Memory &o) const { return timestamp < o.timestamp; }
    bool operator>(const Memory &o) const { return timestamp > o.timestamp; }
    bool operator>=(const Memory &o) const { return timestamp >= o.timestamp; }
    bool operator<=(const Memory &o) const { return timestamp <= o.timestamp; }
};

template <typename T> class DecreasingList {
private:
    forward_list<T> data;

public:
    DecreasingList() = default;

    void add(const T &value) {
        if (data.empty() || value >= data.front()) {
            data.push_front(value);
        } else {
            data.push_front(value);
            data.sort(greater<T>());
        }
    }

    const T *find(const T &value) const {
        for (const auto &item : data) {
            if (item == value)
                return &item;
            if (item < value)
                break;
        }
        return nullptr;
    }

    void erase(const T &value) {
        data.remove_if([&value](const T &item) { return item == value; });
    }

    const T &front() const { return data.front(); }
    bool empty() const { return data.empty(); }
    void clear() { data.clear(); }
};

void read_exactly(char *b, size_t n) {
    for (size_t r = 0; r < n; cin.clear()) {
        cin.read(b + r, n - r);
        r += cin.gcount();
    }
}

tag_t hash_tag(const char *s, size_t len) {
    tag_t total = 0, b;
    size_t i = 0, dim = sizeof(tag_t);

    for (; i + dim <= len; i += dim) {
        memcpy(&b, s + i, dim);
        total += b;
    }

    if (i < len) {
        b = 0;
        memcpy(&b, s + i, len - i);
        total += b;
    }

    return total;
}

void menu() {
    cout << "1. Create new memory" << endl;
    cout << "2. Add tag to memory" << endl;
    cout << "3. Edit tag" << endl;
    cout << "4. Delete memory" << endl;
    cout << "5. Recall memory" << endl;
    cout << "> ";
}

DecreasingList<Memory> memories;

int main() {
    int choice;
    int idx, len;
    int64_t ts;
    const Memory *it;
    tag_t tag;
    char input[0x10] = {0};

    cout << "Welcome to my secure memory saver app :)" << endl;
    while (cin.good()) {
        it = nullptr;
        menu();

        if (!(cin >> choice)) break;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch (choice) {
        case 1:
            cout << "Timestamp: ";
            if (!(cin >> ts)) break;
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Description: ";
            read_exactly(input, sizeof(input));
            input[sizeof(input) - 1] = '\0';
            memories.add(Memory(ts, input));
            break;

        case 2:
            cout << "Timestamp: ";
            if (!(cin >> ts)) break;
            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            cout << "Tag: ";
            read_exactly(input, sizeof(input));
            tag = hash_tag(input, sizeof(input));

            it = memories.find(Memory(ts));
            if (it != nullptr) {
                it->tags.push_back(tag);
            }
            break;

        case 3:
            cout << "Timestamp: ";
            if (!(cin >> ts))
                break;
            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            cout << "Tag idx: ";
            cin >> idx;
            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            cout << "Tag: ";
            read_exactly(input, sizeof(input));
            tag = hash_tag(input, sizeof(input));

            it = memories.find(Memory(ts));
            if (it != nullptr) {
                len = it->tags.size();
                if (len) {
                    it->tags[abs(idx) % len] = tag;
                }
            }
            break;

        case 4:
            cout << "Timestamp: ";
            if (!(cin >> ts))
                break;

            memories.erase(Memory(ts));
            break;

        case 5:
            cout << "Work in progress :)" << endl;
            break;

        default:
            break;
        }
    }
}
