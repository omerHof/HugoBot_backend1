import itertools
from abc import abstractmethod

import numpy as np
from scipy.stats import entropy

from constants import EntityClassRelationsColumns, DatasetColumns
from temporal_abstraction.discretization.supervised import Supervised
from temporal_abstraction.discretization.methods.td4c_persist.shared_functions import symmetric_kullback_leibler, \
    candidate_selection

"""
    Temporal Discretization for Classification
    discretization method
"""


class TD4C(Supervised):

    def _generate_cutpoints(self, prop_df):
        prop_df = prop_df.merge(self._entity_class_relations, on=DatasetColumns.EntityID)
        bool_ig = False
        if type(self) is TD4CEntropyIG:
            bool_ig = True
            self.__class__ = TD4CEntropyIG
        return candidate_selection(
            prop_df,
            self._nb_bins,
            lambda df, cutoffs, *args: self.__DDM_scoring_function(df, cutoffs, *args),
            bool_ig
            )

    def __DDM_scoring_function(self, df, cutoffs, *args):
        """
        A template method which uses the _distance_measure method to get the distance between 2
        distributions.
        :param df:
        :param cutoffs:
        :return:
        """
        # we re-map the classes to integers since classes could also be strings
        class_mapping = {id: ind for id, ind in zip(df[EntityClassRelationsColumns.ClassID].unique(),
                                                    itertools.count())}
        nb_classes = len(class_mapping)

        df[EntityClassRelationsColumns.ClassID] = df[EntityClassRelationsColumns.ClassID].map(class_mapping)

        class_distribs = np.zeros((nb_classes, len(cutoffs) + 1))
        for class_id, class_df in df.groupby(EntityClassRelationsColumns.ClassID):
            # if there are several entries with the same EntityID and ClassID
            # it will cause problems because they will be counted more than once
            freq = class_df.Bin.value_counts()
            class_distribs[class_id, freq.index.astype(
                np.int)] = freq.values / class_df.Bin.size  # every entry is worth 1, so the sum of the item frequencies is the same as the number of entries

        if args:
            return self._set_entropy_ig(df, args[0])
        else:
            score = 0
            for i in range(nb_classes):
                for j in range(i + 1, nb_classes, 1):
                    score += self._distance_measure(class_distribs[i], class_distribs[j])
            return score

    @abstractmethod
    def _distance_measure(self, p, q):
        """ This abstract method is shared between TD4C methods.
            Each subclass uses a different distance measure. """

    def _set_entropy_ig(self, df, last_entropy):
        """ This defines a method for TD4C Entropy Information Gain. """


class TD4CKullbackLeibler(TD4C):

    def _distance_measure(self, p, q):
        return symmetric_kullback_leibler(p, q)


class TD4CEntropy(TD4C):
    def _distance_measure(self, p, q):
        return abs(entropy(p) - entropy(q))


class TD4CEntropyIG(TD4C):
    def _distance_measure(self, p, q):
        return abs(entropy(p) - entropy(q))

    def _calculate_ig(self, target_class):
        elements, counts = np.unique(target_class, return_counts=True)
        return np.sum([(-counts[i]/np.sum(counts))*np.log2(counts[i]/np.sum(counts)) for i in range(len(elements))])

    def _set_entropy_ig(self, df, last_entropy):
        if last_entropy < 0:
            last_entropy = self._calculate_ig(df["ClassID"])
        values, counts = np.unique(df["Bin"], return_counts=True)
        curr_entropy = np.sum([(counts[i]/np.sum(counts))*self._calculate_ig(df.where(df["Bin"] == values[i]).dropna()["ClassID"]) for i in range(len(values))])
        information_gain = last_entropy - curr_entropy
        return information_gain, curr_entropy


class TD4CCosine(TD4C):
    def _distance_measure(self, p, q):
        return np.dot(p, q) / np.sqrt(p.dot(p) * q.dot(q))


class TD4CDiffSum(TD4C):
    def _distance_measure(self, p, q):
        return np.sum(np.abs(p - q))


class TD4CDiffMax(TD4C):
    def _distance_measure(self, p, q):
        return np.max(np.abs(p - q))
