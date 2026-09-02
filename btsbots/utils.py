import re

def validate_bts_username(username: str) -> tuple[bool, str]:
    """
    BitShares 最严格及最便宜账号名的通用校验规则:
    1. 字符构成要求仅限小写字母：必须使用英文小写字母（a-z），不支持任何大写字母。
    2. 数字：可以使用数字（0-9）。
    3. 特殊符号：仅允许使用连字符（-），且连字符不能连续出现，也不能作为开头或结尾。
    4. 不支持空格与特殊字符：不能包含空格、下划线（_）、点（.）等其他符号。
    5. 长度限制：账户名长度限制在 8 到 30 个字符之间（或通用 3-63，此处按最严要求 8-30）。
    6. 开头字符：必须以字母开头。
    """
    if not isinstance(username, str):
        return False, "用户名必须是字符串"

    # 长度限制 8 到 30 个字符
    if not (8 <= len(username) <= 30):
        return False, "账户名长度必须在 8 到 30 个字符之间"

    # 必须以小写字母开头
    if not re.match(r"^[a-z]", username):
        return False, "账户名必须以英文小写字母（a-z）开头"

    # 不能包含连续的连字符
    if "--" in username:
        return False, "账户名中不能包含连续的连字符（--）"

    # 不能以连字符结尾
    if username.endswith("-"):
        return False, "账户名不能以连字符（-）结尾"

    # 综合正则匹配：仅允许小写字母、数字、单个连字符
    if not re.match(r"^[a-z][a-z0-9\-]*[a-z0-9]$", username) and len(username) > 1:
        return False, "账户名仅允许包含小写字母 (a-z)、数字 (0-9) 以及非连续的连字符 (-)"

    # 额外防范点与下划线
    if "." in username or "_" in username or " " in username:
        return False, "账户名不能包含点（.）、下划线（_）或空格"

    return True, "校验通过"

