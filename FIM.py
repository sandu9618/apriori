import numpy as np
import pandas as pd
import apriori_functions
import define_


class FIM(object):
    def __init__(self, path) -> None:
        """
        :param path: The path to the csv file contains dataset
        """
        self.path = path
        self.freqItems, self.suppData, self.rules, self.finalRules, oneHotEncodedDF = None, None, None, None, None

    def findFreqItemSet(self):
        dataSet = pd.read_csv(self.path)
        dataSet = apriori_functions.preProcessing(dataSet)
        self.freqItems, self.suppData = apriori_functions.apriori(dataSet.to_numpy(), minSupport=0.1)
        return self.freqItems, self.suppData

    def findAssocRules(self):
        self.rules = apriori_functions.generateRules(self.freqItems, self.suppData, minConf=0.5)
        return self.rules

    def rulesToDataFrame(self):
        cols = [define_.ITEM_A, define_.ITEM_B, define_.CONFIDENCE_AB, define_.SUPPORT_AB, define_.SUPPORT_B, define_.LIFT]
        self.finalRules = pd.DataFrame(self.rules, columns=cols)
        self.finalRules[define_.ITEM_A] = self.finalRules.apply(
            lambda row: apriori_functions.convertToStringList(str(row[define_.ITEM_A])), axis=1)
        self.finalRules[define_.ITEM_B] = self.finalRules.apply(
            lambda row: apriori_functions.convertToStringList(str(row[define_.ITEM_B])), axis=1)
        self.finalRules.to_csv(define_.FINAL_RULES_FILE_PATH)
        return self.finalRules

    def oneHotEncode(self):
        featureList = [define_.P_TCP, define_.P_HTTP, define_.P_SSH, define_.P_DNS, define_.P_ARP, define_.P_SSHV2,
                       define_.L_0, define_.L_1, define_.L_2, define_.L_3, define_.D_80, define_.D_42972, define_.D_34230,
                       define_.D_50822, define_.D_53, define_.D_22, define_.D_56040, define_.D_161, define_.D_443,
                       define_.R_PUBLIC, define_.R_PRIVATE, define_.R_NON, define_.X_IN, define_.X_OUT, define_.X_NON,
                       define_.C_A1, define_.C_A2, define_.C_A3]
        return pd.DataFrame(apriori_functions.oneHot(self.finalRules, featureList), columns=featureList)
