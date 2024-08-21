from abc import ABC, abstractmethod

class checkBase(ABC):
    '''
    漏洞扫描基类
    '''
    def __init__(self,path_all) -> None:
        self.path_all = path_all
    @abstractmethod
    def scan(self) -> None:
        pass
