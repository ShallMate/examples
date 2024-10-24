import spu
import secretflow as sf
import numpy as np
import pdb
from joblib import Parallel, delayed
import random

sf.shutdown()

sf.init(['sender', 'receiver'], address='local')

ss_config = sf.utils.testing.cluster_def(
    parties=['sender', 'receiver'],
    runtime_config={
        'protocol': spu.spu_pb2.SEMI2K,
        'field': spu.spu_pb2.FM64,
        'enable_pphlo_profile': True,
        'enable_hal_profile':True,
    },
)

spu_device2 = sf.SPU(ss_config)
sender, receiver = sf.PYU('sender'), sf.PYU('receiver')


n = int((1<<20)* 1.27)  
dnum = 5
#t = np.random.randint(1, dnum+1)
t = 1

t_vector = np.full(n, t, dtype=np.int32)


ops = {">":[0, 2, -1],
       ">=":[1,0.5,-0.5],
       "<":[0,-0.5,0.5],
       "<=":[1,-2,1],
       "=":[1,-1.5,0.5],
       "/":[1,0,0]
       } 

symbols = [">", "<", "=", ">=", "<=","/"]





# dnum 的长度


# 生成 dnum 长的随机符号列表
op_list = [random.choice(symbols) for _ in range(dnum)]



predicate_num = np.random.randint(np.iinfo(np.int32).min, np.iinfo(np.int32).max, size=dnum, dtype=np.int32)


predicate_matrix = np.tile(predicate_num, (n, 1))


sender_features = np.random.randint(np.iinfo(np.int32).min, np.iinfo(np.int32).max, size=(n, dnum), dtype=np.int32)

def greater(x, y):
    return (x>y)

def smaller(x, y):
    return (x<y)

def compare(x,y):
    return x.astype(int)+(y.astype(int)<<1)

def sub(x,y):
    return x-y

def poly(x,i,op):
    return op[0]+op[1]*x[:,i]+op[2]*x[:,i]**2

def im(x,y):
    return x+y

ss_ops = sf.to(receiver,ops)

def COMPARE():
    x = sf.to(sender,sender_features)
    y = sf.to(receiver,predicate_matrix)
    op_greater = spu_device2(greater)(x,y)
    op_smaller = spu_device2(smaller)(x,y)
    res = spu_device2(compare)(op_greater,op_smaller)
    return res 

def PPT(res):
    ppts = []
    for i in range(0,dnum):
        if op_list[i] ==">":
            ss_ops = sf.to(receiver,ops[">"])
            ppt = spu_device2(poly)(res,i,ss_ops)
            ppts.append(ppt)
        elif op_list[i] ==">=":
            ss_ops = sf.to(receiver,ops[">="])
            ppt = spu_device2(poly)(res,i,ss_ops)
            ppts.append(ppt)
        elif op_list[i] =="<":
            ss_ops = sf.to(receiver,ops["<"])
            ppt = spu_device2(poly)(res,i,ss_ops)
            ppts.append(ppt)
        elif op_list[i] =="<=":
            ss_ops = sf.to(receiver,ops["<="])
            ppt = spu_device2(poly)(res,i,ss_ops)
            ppts.append(ppt)
        elif op_list[i] =="=":
            ss_ops = sf.to(receiver,ops["="])
            ppt = spu_device2(poly)(res,i,ss_ops)
            ppts.append(ppt)
        else:
            ss_ops = sf.to(receiver,ops["/"])
            ppt = spu_device2(poly)(res,i,ss_ops)
            ppts.append(ppt)
    return ppts

def IM(ppts):
    srres = ppts[0]
    for i in range(1,dnum):
        srres = spu_device2(im)(srres,ppts[i])
    return srres

def judge(x,y):
    return x>=y

res = COMPARE()
ppts = PPT(res)
srres = IM(ppts)

t_share = sf.to(receiver,t_vector)
srres = spu_device2(judge)(srres,t_share)

receivershare = np.random.randint(0, 65536, size=n, dtype=np.int32)
ones_vector = np.ones(n, dtype=np.int32)

spu_receivershare = sf.to(receiver,receivershare)

spu_sendershare = spu_device2(sub)(srres,spu_receivershare)

sendershare = sf.reveal(spu_sendershare)
sendershare = sendershare.astype(int)

receivershare = ones_vector - receivershare
#print(len(receivershare))

with open('../../bazel-bin/examples/pfrpsi/receivershare', 'w') as file:
    for value in receivershare:
        file.write(f"{value}\n")

with open('../../bazel-bin/examples/pfrpsi/sendershare', 'w') as file:
    for value in sendershare:
        file.write(f"{value}\n")