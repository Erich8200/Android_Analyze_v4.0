class c:
    __a = [] # 默认会被当作静态变量
    __b = 0  # int和字符串没这个问题
    __c = ''

    def __init__(self):
        self.__a = [] # 一定要在__init__中加上初始化列表类型的语句，否则类中列表默认当作静态变量处理

    def change_a(self):
        if self.__a == []:
            self.__a.append('f') # hope do this
        else:
            self.__a.append('u')

    def get_a(self):
        return self.__a

    def change_b(self):
        if self.__b == 0:
            self.__b = 1
        else:
            self.__b = 2

    def get_b(self):
        return self.__b

    def change_c(self):
        if self.__c == '':
            self.__c = "fuck"
        else:
            self.__c = "shit"

    def get_c(self):
        return self.__c

    # def __del__(self):
    #     self.__a = []

# for i in range(0,5):
#     a = c()
#     a.change_a()
#     a.change_b()
#     a.change_c()
#     print(a.get_a())
#     print(a.get_b())
#     print(a.get_c())
#     # del a

print('aaaaa')
print('aaa\rb')
print(str(100%100))