from src.utils import file_utils

def test_load_usernames(tmp_path):
    file = tmp_path / "users.txt"
    file.write_text("admin\nuser\n")
    users = file_utils.load_usernames(str(file))
    assert users == ["admin", "user"]
