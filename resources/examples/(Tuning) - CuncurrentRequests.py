USER_FILE = "E:\\Apps\\SecLists-2025.1\\Usernames\\top-usernames-shortlist.txt"   # <-- set your path (use forward slashes or double backslash)
PASS_FILE = "E:\\Apps\\SecLists-2025.1\\Usernames\\top-usernames-shortlist.txt"    # <-- set your path

def load_lines(path):
    try:
        p = path.replace("\\", "/")
        f = open(p, "r")
        lines = [l.rstrip() for l in f.readlines() if l.rstrip()]
        f.close()
        return lines
    except Exception as e:
        print("ERROR opening %s : %s" % (path, str(e)))
        return []

def count_combos():
    users = load_lines(USER_FILE)
    passes = load_lines(PASS_FILE)
    u = len(users)
    p = len(passes)
    combos = u * p
    print("Users: %d, Passwords: %d, Combos: %d" % (u, p, combos))
    return u, p, combos

# run when script is loaded
count_combos()
