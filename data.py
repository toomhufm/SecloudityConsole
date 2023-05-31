def GetUser(id):
   for i in session:
      for key in i.keys():
         if i[key][0] == id:
            return key
         
session = [{'a':['b','']},{'c':'d'}]

def GetDictValue(param,dict):
    for i in dict:
      for key in i.keys():
         if key == param:
            return i[key]


for i in session:
   for j in i.keys():
      if 'a' == j:
         print(i[j][1])