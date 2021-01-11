import numpy as np
import pandas as pd
from ipaddress import ip_address, ip_network
import re
import define_


def is_valid_ipv4(ip):
    """Validates IPv4 addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None


def is_valid_ipv6(ip):
    """Validates IPv6 addresses.
    """
    pattern = re.compile(r"""
        ^
        \s*                         # Leading whitespace
        (?!.*::.*::)                # Only a single whildcard allowed
        (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
        (?:                         # Repeat 6 times:
            [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
        ){6}                        #
        (?:                         # Either
            [0-9a-f]{0,4}           #   Another group
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
            [0-9a-f]{0,4}           #   Last group
            (?: (?<=::)             #   Colon iff preceeded by exacly one colon
             |  (?<!:)              #
             |  (?<=:) (?<!::) :    #
             )                      # OR
         |                          #   A v4 address with NO leading zeros
            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            (?: \.
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            ){3}
        )
        \s*                         # Trailing whitespace
        $
    """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
    return pattern.match(ip) is not None


def is_valid_ip(ip):
    """Validates IP addresses.
    """
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def isPrivate(IP: str) -> bool:
    return True if ip_address(IP).is_private else False


def check_ip(ip: str) -> str:
    if is_valid_ip(ip):
        if isPrivate(ip):
            return define_.R_PRIVATE
        else:
            return define_.R_PUBLIC
    else:
        return define_.R_NON


def check_direction(ip: str, cidrs: list) -> str:
    if is_valid_ip(ip):
        count = 0
        for cidr in cidrs:
            if ip_address(ip) in ip_network(cidr):
                count = count + 1
        if count > 1:
            return define_.X_IN
        else:
            return define_.X_OUT
    else:
        return define_.X_NON


def preProcessing(dataSet):
    length_max = dataSet['Length'].max()
    length_min = dataSet['Length'].min()

    cidr = define_.CIDR

    # print(length_max)
    dataSet['Length'] = np.where(np.logical_or(dataSet.Length < 60, dataSet.Length == 60), 0, dataSet.Length)
    dataSet['Length'] = np.where(np.logical_and(dataSet.Length > 60, dataSet.Length < 1000), 1, dataSet.Length)
    dataSet['Length'] = np.where(np.logical_or(dataSet.Length > 1000, dataSet.Length == 1000), 2, dataSet.Length)

    dataSet = dataSet[dataSet['Destination'].notnull()]

    dataSet['Dst_ip_range'] = dataSet.apply(lambda row: check_ip(str(row["Destination"])), axis=1)
    dataSet['Direction'] = dataSet.apply(lambda row: check_direction(str(row["Destination"]), cidr), axis=1)

    dataSet = dataSet.drop(['Info'], axis=1)
    dataSet = dataSet.drop(['Destination'], axis=1)
    dataSet = dataSet.drop(['Source'], axis=1)
    dataSet = dataSet.drop(['Time'], axis=1)
    dataSet = dataSet.drop(['No.'], axis=1)
    dataSet = dataSet.drop(['Src_port'], axis=1)

    dataSet['Length'] = dataSet['Length'].astype('str')
    dataSet['Dst_port'] = dataSet['Dst_port'].astype('str')
    dataSet['Class'] = dataSet['Class'].astype('str')
    dataSet['Protocol'] = dataSet['Protocol'].astype('str')
    # dataSet['Destination'] = dataSet['Destination'].astype('str')

    dataSet['Protocol'] = 'p-' + dataSet['Protocol']
    dataSet['Length'] = 'l-' + dataSet['Length']
    dataSet['Dst_port'] = 'd-' + dataSet['Dst_port']
    dataSet['Class'] = 'c-' + dataSet['Class']

    return dataSet


def createC1(dataSet):
    C1 = []
    for transaction in dataSet:
        for item in transaction:
            if not [item] in C1:
                C1.append([item])

    C1.sort()
    print(C1)
    return list(map(frozenset, C1))  # use frozen set so we
    # can use it as a key in a dict


def scanD(D, Ck, minSupport):  # generates L and dictionary of support data
    ssCnt = {}
    for tid in D:
        for can in Ck:
            if can.issubset(tid):
                if not can in ssCnt:
                    ssCnt[can] = 1
                else:
                    ssCnt[can] += 1
    numItems = float(len(D))
    retList = []
    supportData = {}
    for key in ssCnt:
        support = ssCnt[key] / numItems
        if support >= minSupport:
            retList.insert(0, key)
        supportData[key] = support
    return retList, supportData


def aprioriGen(Lk, k):  # creates Ck
    retList = []
    lenLk = len(Lk)
    for i in range(lenLk):
        for j in range(i + 1, lenLk):
            L1 = list(Lk[i])[:k - 2]
            L2 = list(Lk[j])[:k - 2]
            L1.sort()
            L2.sort()
            if L1 == L2:  # if first k-2 elements are equal
                retList.append(Lk[i] | Lk[j])  # set union
    return retList


def apriori(dataSet, minSupport=0.1):
    C1 = createC1(dataSet)  # Create candidate itemsets of size one
    D = list(map(set, dataSet))  # make dataset in the setform
    L1, supportData = scanD(D, C1, minSupport)
    ''' returns itemsets that meet
                minimum requirement and dictionary with support values
                '''
    L = [L1]
    k = 2
    while len(L[k - 2]) > 0:
        Ck = aprioriGen(L[k - 2], k)  # To produce candidate itemset of size k
        Lk, supK = scanD(D, Ck, minSupport)  # scan DB to get Lk
        supportData.update(supK)
        L.append(Lk)
        k += 1
    return L, supportData


def generateRules(L, supportData, minConf=0.7):  # supportData is a dict coming from scanD
    # freqt = freq(L)
    # print(pd.Series( (v[0] for v in L) ))
    bigRuleList = []
    for i in range(1, len(L)):  # only get the sets with two or more items
        for freqSet in L[i]:
            H1 = [frozenset([item]) for item in freqSet]
            if i > 1:
                rulesFromConseq(freqSet, H1, supportData, bigRuleList, minConf)
            else:
                calcConf(freqSet, H1, supportData, bigRuleList, minConf)
    return bigRuleList


def calcConf(freqSet, H, supportData, brl, minConf=0.7):
    prunedH = []  # create new list to return
    list_item = []
    for conseq in H:
        confAB = supportData[freqSet] / supportData[freqSet - conseq]  # calc
        confBA = supportData[freqSet] / supportData[conseq]
        lift = supportData[freqSet] / supportData[freqSet - conseq] * supportData[conseq]
        if (confAB >= minConf) and (
                conseq in [frozenset({define_.C_A1}), frozenset({define_.C_A2}), frozenset({define_.C_A3})]):
            print(freqSet - conseq, '-->', conseq, 'confAB:', confAB, 'confBA:', confBA, 'supportAB:',
                  supportData[freqSet], 'supportA:', supportData[freqSet - conseq], 'supportB:', supportData[conseq],
                  'lift:', lift)
            brl.append((list(freqSet - conseq), list(conseq), confAB, confBA, supportData[freqSet],
                        supportData[freqSet - conseq], supportData[conseq], lift))
            prunedH.append(conseq)
    return prunedH


def rulesFromConseq(freqSet, H, supportData, brl, minConf=0.7):
    m = len(H[0])
    if len(freqSet) > (m + 1):  # try further merging
        Hmp1 = aprioriGen(H, m + 1)  # create Hm+1 new candidates
        Hmp1 = calcConf(freqSet, Hmp1, supportData, brl, minConf)
        if len(Hmp1) > 1:  # need at least two sets to merge
            rulesFromConseq(freqSet, Hmp1, supportData, brl, minConf)


def convertToStringList(string):
    a = string.replace('\'', '')
    b = a.replace('[', '')
    c = b.replace(']', '')
    l = c.split(", ")
    return l


def oneHot(dataSet, featureList):
    r, c = dataSet.shape
    zeroArray = np.zeros(shape=(r, len(featureList)))
    for index, row in dataSet.iterrows():
        ItemA = row[define_.ITEM_A]
        ItemB = row[define_.ITEM_B]

        for item in ItemA:
            if item in featureList:
                indexA = featureList.index(item)
                zeroArray[index][indexA] = 1

        if ItemB[0] in featureList:
            indexB = featureList.index(ItemB[0])
            zeroArray[index][indexB] = 1

    return zeroArray


def freqItemToDF(freq):
    freqArr = []
    for i in range(len(freq) - 1):
        len_ = len(freq[i])
        for j in range(len_):
            arr = np.array(['*     ', '*     ', '*     ', '*         ', '*       ', '*      '])
            item = list(freq[i][j])
            for k in range(len(item)):
                kItem = item[k]
                if 'p-' in kItem:
                    arr[0] = kItem
                elif 'l-' in kItem:
                    arr[1] = kItem
                elif 'd-' in kItem:
                    arr[2] = kItem
                elif 'r-' in kItem:
                    arr[3] = kItem
                elif 'x-' in kItem:
                    arr[4] = kItem
                elif 'c-' in kItem:
                    arr[5] = kItem
            freqArr.append(arr)

    colmn = ["Protocol", "Length", "Dst-port", "Dst-ip-range", "Direction", "Class"]
    freqDF = pd.DataFrame(freqArr, columns=colmn)

    return freqDF


def frozenSetToSetForm(froz):
    arr1 = []
    for i in range(len(froz) - 1):
        arr = []
        len_ = len(froz[i])
        for j in range(len_):
            arr.append(set(list(froz[i][j])))
        arr1.append(arr)

    return arr1


def findMFI(freqItems):
    arr = frozenSetToSetForm(freqItems)
    mfi = []
    for i in range(len(freqItems) - 1):
        for j in range(len(freqItems[i])):
            count = 0
            for k in range(len(freqItems[i + 1])):
                if arr[i + 1][k].issuperset(arr[i][j]):
                    count = count + 1
            if count == 0:
                mfi.append(arr[i][j])

    return mfi
