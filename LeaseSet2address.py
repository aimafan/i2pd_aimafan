import requests


def hash2address(base32_hash):
    # 去掉"="字符
    str_without_equals = base32_hash.replace("=", "")
    # 将所有大写字母转换为小写
    lowercase_str = str_without_equals.lower()

    address = ".".join([lowercase_str, "b32", "i2p"])
    address = "http://" + address
    return address


def request(address):
    # 代理服务器的IP地址和端口
    proxies = {
        "http": "http://127.0.0.1:4444",
    }

    # 发送请求
    try:
        print(address)
        response = requests.get(address, proxies=proxies)

        # 检查请求是否成功
        if response.status_code == 200:
            print("成功获取网页内容")
            # 这里可以处理获取到的网页内容，例如打印出来
            print(response.text)
        else:
            print("请求失败，状态码：", response.status_code)
    except requests.exceptions.ProxyError:
        print("代理连接出错")
    except requests.exceptions.RequestException as e:
        print("请求出错：", e)


def read_base32_from_log(log_path):
    base32_hashs = []
    with open(log_path, "r") as file:
        for line in file:
            base32_hashs.append(line.strip().split(" ")[-1])
    return base32_hashs


def action(log_path):
    base32_hashs = read_base32_from_log(log_path)
    for base32_hash in base32_hashs:
        address = hash2address(base32_hash)
        request(address)


if __name__ == "__main__":
    action("./aimafan.log")
