#pragma once

#include <functional>
#include <string_view>
#include <vector>

#define SQLITE_OPEN_READWRITE        0x00000002  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_CREATE           0x00000004  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_NOMUTEX          0x00008000  /* Ok for sqlite3_open_v2() */

#define SQLITE_OK           0   /* Successful result */
#define SQLITE_ROW         100  /* sqlite3_step() has another row ready */
#define SQLITE_DONE        101  /* sqlite3_step() has finished executing */

struct sqlite3;
struct sqlite3_stmt;

extern const char *(*sqlite3_errstr)(int);

// Transparent wrappers of sqlite3_stmt
struct DbValues {
    const char *get_text(int index) const;
    std::string_view get_str(int index) const {
        const char *s = get_text(index);
        return s ? std::string_view{s} : std::string_view{};
    }
    int get_int(int index) const;
    ~DbValues() = delete;
};
struct DbStatement {
    int bind_text(int index, std::string_view val);
    int bind_int64(int index, int64_t val);
    ~DbStatement() = delete;
};

using ColumnList = std::vector<std::string_view>;

sqlite3 *open_and_init_db();

/************
 * C++ APIs *
 ************/

using db_exec_callback = std::function<void(const ColumnList &, const DbValues &)>;

struct DbArg {
    enum {
        INT,
        TEXT,
    } type;
    int64_t int_val = 0;
    std::string_view str_val{};
    DbArg(int64_t v) : type(INT), int_val(v) {}
    DbArg(std::string_view v) : type(TEXT), str_val(v) {}
};

struct DbArgs {
    DbArgs() : curr(0) {}
    DbArgs(std::initializer_list<DbArg> list) : args(list), curr(0) {}
    int operator()(int index, DbStatement &stmt);
    bool empty() const { return args.empty(); }
private:
    std::vector<DbArg> args;
    size_t curr;
};

bool db_exec(const char *sql, DbArgs args = {}, db_exec_callback exec_fn = {});

template<typename T>
concept DbData = requires(T t, const ColumnList &c, const DbValues &v) { t(c, v); };

template<DbData T>
bool db_exec(const char *sql, DbArgs args, T &data) {
    return db_exec(sql, std::move(args), (db_exec_callback) std::ref(data));
}
