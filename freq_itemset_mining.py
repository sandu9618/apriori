import pandas as pd
from mlxtend.frequent_patterns import apriori
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import association_rules

import define_
import apriori_functions


def freq_itemset_mining(dataSet, min_support):
    oneHotEncodedDF = None
    print("Starting FIM")

    print("Transaction Encoder is started")
    te = TransactionEncoder()
    te_ary = te.fit(dataSet.to_numpy()).transform(dataSet.to_numpy())
    transformed_df = pd.DataFrame(te_ary, columns=te.columns_)

    print("Transaction Encoder is finished")
    print("Apriori is started")

    freqItemsets = apriori(transformed_df, min_support=min_support, use_colnames=True)

    print("Apriori is finished")
    print("Association rules mining is started")
    rules = association_rules(freqItemsets, metric="lift", min_threshold=0.1)
    rules = rules[(rules['consequents'] == {'c-A1'}) |
                  (rules['consequents'] == {'c-A2'}) |
                  (rules['consequents'] == {'c-A3'}) |
                  (rules['consequents'] == {'c-A4'}) |
                  (rules['consequents'] == {'c-A5'}) &
                  (('c-A1' not in (rules.antecedents.to_list())) |
                   ('c-A2' not in (rules.antecedents.to_list())) |
                   ('c-A3' not in (rules.antecedents.to_list())) |
                   ('c-A4' not in (rules.antecedents.to_list())) |
                   ('c-A5' not in (rules.antecedents.to_list()))
                   )]
    rules['antecedents'] = rules.apply(lambda row: apriori_functions.convertToStringList(str(list(row['antecedents']))),
                                       axis=1)
    rules['consequents'] = rules.apply(lambda row: apriori_functions.convertToStringList(str(list(row['consequents']))),
                                       axis=1)
    rules.reset_index(inplace=True)

    print("Association rules mining is finished")

    print("One Hot encoding is started")
    # cols = dataSet[dataSet[:-1]]
    cols = dataSet.columns[:-1]
    print(cols)
    featureList = [define_.P_TCP, define_.P_HTTP, define_.P_SSH, define_.P_DNS, define_.P_ARP, define_.P_SSHV2,
                   define_.L_0, define_.L_1, define_.L_2, define_.D_80, define_.D_42972, define_.D_34230,
                   define_.D_50822, define_.D_53, define_.D_22, define_.D_56040, define_.D_161, define_.D_443,
                   define_.R_PUBLIC, define_.R_PRIVATE, define_.R_NON, define_.X_IN, define_.X_OUT, define_.X_NON]

    x = pd.DataFrame(apriori_functions.oneHot(rules, featureList), columns=featureList)
    if len(x) > 0:
        y = rules.apply(
            lambda row: str(row["consequents"][0].replace('[', '').replace(']', '')),
            axis=1)

    return x, y, rules


if __name__ == '__main__':
    print("Load data Set")
    dataSet = pd.read_csv(define_.DATA_FILE_PATH)
    print("Start Pre-processing")
    dataSet = apriori_functions.preProcessing(dataSet)
    print("End pre-processing")
    x, y, rules = freq_itemset_mining(dataSet, 0.005)
