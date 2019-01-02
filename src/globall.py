'''
    @author - mrdrivingduck
    @version - 2018.12.31
    @function - 
        Global variables.
'''

from config import Config
from util.ringbuffer import RingBuffer

conf = Config("../conf/localDebugConfig.ini")
buff = RingBuffer(conf.getBufferSize())    
