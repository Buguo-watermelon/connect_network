import base64
import json
import os
import re
import sys
import winreg
import time
from pprint import pprint

import requests
from psutil import net_if_addrs

ret_message_map = {
    0: "成功", 1: "账号或密码不对，请重新输入", 2: "终端IP已经在线", 3: "系统繁忙，请稍后再试",
    4: "发生未知错误，请稍后再试", 5: "REQ_CHALLENGE 失败，请联系AC确认", 6: "REQ_CHALLENGE 超时，请联系AC确认",
    7: "Radius 认证失败", 8: "Radius 认证超时", 9: "Radius 下线失败", 10: "Radius 下线超时",
    11: "发生其他错误，请稍后再试", 998: "Portal协议参数不全，请稍后再试"
}
mac = "000000000000"


def get_ip():
    """
    获取用户待登录校园网的ip
    """
    network_adapters_info = get_network_adapters_info()  # 获取网络适配器信息
    pprint(network_adapters_info)  # 打印网络适配器信息
    choice = input("请输入下标以选择要用于登录校园网的网卡：")
    return network_adapters_info[int(choice)]['ip_address']


def get_network_adapters_info():
    """
    获取网络适配器信息
    """
    adapters_info = {}  # 存储适配器信息的字典
    adapters = net_if_addrs()  # 获取所有网络适配器的信息

    # 遍历每个适配器的信息
    for index, (adapter_name, adapter_info) in enumerate(adapters.items()):
        adapter_details = {}  # 存储适配器详细信息的字典

        # 遍历适配器的每个地址信息
        for item in adapter_info:
            address_family = item.family  # 地址族

            if address_family == 2:  # AF_INET 表示IPv4地址
                adapter_details['adapter_name'] = adapter_name  # 适配器名称
                adapter_details["address_family"] = "IPv4"  # 地址族类型
                adapter_details["ip_address"] = item.address  # IPv4地址

        adapters_info[index] = adapter_details  # 将适配器详细信息添加到字典中

    return adapters_info  # 返回适配器信息字典


def get_current_dir():
    """
    获取当前目录的绝对路径
    """
    if os.name == 'nt':  # Windows系统
        return os.path.abspath(os.getcwd())  # 返回当前目录的绝对路径
    else:
        print("非Windows系统，程序无法继续运行！")


def get_cache_file_path():
    """
    获取缓存文件的路径
    """
    return get_current_dir() + os.path.sep + ".anhui_wifi"  # 拼接当前目录和缓存文件名形成路径


def add_to_registry():
    """
    将程序添加到开机自启注册表项
    """
    key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'  # 注册表路径
    value_name = 'Campus_network_automatic_connection'  # 注册表项名称
    value_data = get_self_file_path()  # 程序文件路径

    try:
        # 检查是否已存在注册表项
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        existing_value, value_type = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)

        if existing_value == value_data:
            print('已存在开机自启注册表项，无需添加。')
            return
    except FileNotFoundError:
        pass

    choice = input('是否设置为开机自启动？(1表示同意设置，其他任意键表示不设置)')
    if choice == '1':
        # 添加或更新注册表项
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
        winreg.CloseKey(key)
        print('已设置开机自启动！')
    else:
        print('用户未设置开机自启动。')
        time.sleep(5)


def delete_from_registry():
    """
    从开机自启注册表项中删除程序
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                             winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, 'Campus_network_automatic_connection')
        winreg.CloseKey(key)
        print("注册表项删除成功")
    except FileNotFoundError:
        print("注册表项不存在")


def get_self_file_path():
    """
    获取当前脚本文件的绝对路径
    """
    return os.path.abspath(sys.argv[0])  # 使用sys.argv[0]获取当前脚本文件的路径，并返回其绝对路径


def set_account():
    """
    设置用户账号信息并保存到缓存文件中
    """
    account = input("学号：")
    password = input("密码：")
    ip = get_ip()
    cache_file = open(get_cache_file_path(), "wb")
    cache_file.write(base64.b64encode(account.encode()))  # 将账号进行Base64编码后写入文件
    cache_file.write(os.linesep.encode())  # 写入换行符
    cache_file.write(base64.b64encode(password.encode()))  # 将密码进行Base64编码后写入文件
    cache_file.write(os.linesep.encode())  # 写入换行符
    cache_file.write(base64.b64encode(ip.encode()))  # 将IP地址进行Base64编码后写入文件
    cache_file.close()


def get_account():
    """
    从缓存文件中读取用户账号信息
    """
    cache_file = open(get_cache_file_path(), "r")
    if cache_file is None:
        return None
    account = base64.b64decode(cache_file.readline().strip()).decode()  # 读取并解码账号
    password = base64.b64decode(cache_file.readline().strip()).decode()  # 读取并解码密码
    ip = base64.b64decode(cache_file.readline().strip()).decode()  # 读取并解码IP地址
    cache_file.close()
    return account, password, ip


def main():
    """
    主函数，执行登录操作并处理登录结果
    """
    path = get_self_file_path()  # 获取当前脚本文件的路径
    dir_path = os.path.dirname(path)  # 获取当前脚本文件所在的目录路径
    os.chdir(dir_path)  # 切换工作目录为脚本文件所在的目录

    if not os.path.exists(get_cache_file_path()):
        set_account()  # 如果缓存文件不存在，设置用户账号信息

    user_account, user_password, wlan_user_ip = get_account()  # 获取用户账号信息
    url = "http://172.16.253.3:801/eportal/?c=Portal&a=login&callback=dr1003&login_method=1&user_account=%s" \
          "&user_password=%s&wlan_user_ip=%s&wlan_user_ipv6=&wlan_user_mac=%s&wlan_ac_ip=172.16.253.1" \
          "&wlan_ac_name=&jsVersion=3.3.2&v=892" % (user_account, user_password, wlan_user_ip, mac)
    resp = requests.get(url, headers={"Referer": "http://172.16.253.3/"})  # 发送登录请求

    regex = re.compile(r"dr1003\((.+?)\)", re.I)
    match_res = regex.match(resp.text)
    if match_res is not None:
        respJson = json.loads(match_res.group(1))
        if 'ret_code' not in respJson.keys():
            print('登录成功！')
            add_to_registry()  # 添加到开机自启注册表项
            print('本窗口将于10秒后自动关闭...')
            time.sleep(10)
        else:
            ret_code = respJson['ret_code']
            if ret_code in ret_message_map.keys():
                print(ret_message_map[ret_code])
                add_to_registry()  # 添加到开机自启注册表项
                print('本窗口将于10秒后自动关闭...')
                time.sleep(10)
                # 密码错误，删除配置文件
                if ret_code == 1:
                    os.remove(get_cache_file_path())
                    delete_from_registry()  # 从开机自启注册表项中删除
                    print("检测到密码错误，已经为您删除配置文件，请关闭本窗口后重新输入账号，密码尝试连接！")
                    os.system("pause")
            else:
                print("未知异常，即常见的 AC认证失败")
                os.system("pause")


if __name__ == "__main__":
    main()
