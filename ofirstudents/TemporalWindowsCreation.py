import random

import pandas as pd
import numpy as np


class TemporalWindowsCreation:

    def __init__(self, _window_size, _prediction_period, _overlap_size, _input_path, _output_path, StudyDesign, positiveNegativeRatio, casePositive, caseNegative = 0, controlNegative = 0):

        self.window_size = int(_window_size)
        self.prediction_period = int(_prediction_period)
        self.overlap_size = int(_overlap_size)
        self.EntitiesCounter = 0
        self.StudyDesign = StudyDesign
        self.output_path = _output_path
        self.positiveNegativeRatio = positiveNegativeRatio  #tuple of (positive_number, negative number) reflect P:N
        print("alon alon alon")
        self.creatEntitiesClassDf()
        self.readPickelToDf(_input_path)
        self.creatWindowsByStudyDesine(casePositive, caseNegative, controlNegative)
        self.ChoiceType = "random"
        self.writeDfToPickelTemporalEtities(_output_path)
        #self.writeDfToPickelTemporalEtities(_input_path + _window_size + "_" + _prediction_period + "_" + self.overlap_size)

    def creatWindowsByStudyDesine(self, casePositive, caseNegative, controlNegative):
        if self.StudyDesign == 'CaseCrossover':
            self.create_Case_Windows(casePositive, caseNegative)
        elif self.StudyDesign == 'CaseControl':
            self.create_Case_Windows(casePositive, caseNegative)
            self.create_Control_Windows(controlNegative)
        elif self.StudyDesign == 'CaseControlCrossover':
            self.create_Case_Windows(casePositive, caseNegative)
            self.create_Control_Windows(controlNegative)


    def creatEntitiesClassDf(self):
        """
        This method creat the dataframes we will fill during the windows creation process
        EntitiesMapping: each time window get new id, thise DF map the id of each mew entity
        (time window) to it's original entities id (the paitent id)
        EntitiesClassDf: conatin the class of each time window - positive windows as 1 negative as 0
        windowsTemporalDataDF: dataframes with the new raw data, insted paitent the time windows.
        same format: ['EntityID','TimeStamp','TemporalPropertyID','TemporalPropertyValue']
        :return: None
        """
        self.EntitiesMapping = pd.DataFrame(columns=['OriginalEntityID', 'EntityID'])
        self.EntitiesClassDf = pd.DataFrame(columns=['EntityID', 'ClassID'])
        self.windowsTemporalDataDF = pd.DataFrame(columns=['EntityID', 'TemporalPropertyID', 'TemporalPropertyValue'])

    def readPickelToDf(self, path):
        """
        This method read the rew data from the input path and create the relevent df from it
        :param rew_data:  df, dataframe with the following columns: ['EntityID','TimeStamp','TemporalPropertyID','TemporalPropertyValue']
        TemporalPropertyID = -1: entities class when TemporalPropertyValue set the class value (medatory)
        TemporalPropertyID = -2: define the case outcome timestampe (medatory)
        TemporalPropertyID = -3: define the case event timestampe- rlevnt in caseControl when the windows taken from specific event (optional)
        TemporalPropertyID = -4: define the control chosen outcome timestampe - Knoledge Based (optional)
        TemporalPropertyID = -5: define the control chosen event timestampe - rlevnt in caseControl when the windows taken from specific event (optional)
        :param caseOutcomeTimeStemp:  df, dataframe with the outcome timestampe for all the case entity, the df contain the following columns: ['EntityID', 'TimeStamp']
        :param EntitiesClass: df, dataframe with the entity id and the class of each enitity: ['EntityID', 'Class']
        :return: None
        """
        self.rew_data = pd.read_csv(path)
        self.rew_data['EntityID'] = self.rew_data['EntityID'].astype(int)
        self.rew_data['TemporalPropertyID'] = self.rew_data['TemporalPropertyID'].astype(int)

        # set the case outcomeTimeStemp: if the raw data contain TemporalPropertyID
        self.EntitiesClass = self.rew_data.loc[self.rew_data['TemporalPropertyID']== -1]
        self.EntitiesClass = self.EntitiesClass[['EntityID', 'TimeStamp']]
        self.EntitiesClass = self.EntitiesClass.rename(columns={"TimeStamp": "Class"})

        #self.writeDfToPickelTemporalEtities(path)


        #set the caseOutcomeTimeStemp df
        self.caseOutcomeTimeStemp = {}
        if self.StudyDesign == 'CaseControl' and (self.rew_data['TemporalPropertyID']==-3).any():
            self.caseOutcomeTimeStemp = self.rew_data.loc[self.rew_data['TemporalPropertyID']== -3]
            self.caseOutcomeTimeStemp = self.caseOutcomeTimeStemp[['EntityID', 'TimeStamp']]
        else:
            self.caseOutcomeTimeStemp = self.rew_data.loc[self.rew_data['TemporalPropertyID'] == -2]
            self.caseOutcomeTimeStemp = self.caseOutcomeTimeStemp[['EntityID', 'TimeStamp']]


    def create_Case_Windows(self, casePositive, caseNegative):
        EntitiesIDs = self.EntitiesClass.loc[self.EntitiesClass['Class'] == 1]
        case_rew_data = self.rew_data.loc[self.rew_data['EntityID'].isin(EntitiesIDs.EntityID.unique()), :].copy()
        case_rew_data.reset_index(inplace=True, drop=True)

        #Add outcome and distance columns to the df
        OutcomeTS = self.caseOutcomeTimeStemp[['EntityID', 'TimeStamp']].copy()
        OutcomeTS = OutcomeTS.rename(columns={"TimeStamp": "Outcome_TS"})
        case_rew_data = pd.merge(case_rew_data, OutcomeTS, on="EntityID")
        case_rew_data['Distance'] = case_rew_data['Outcome_TS'] - case_rew_data['TimeStamp']

        #Remove the rows with timestemp after the outcomeTS or from the prediction period
        case_rew_data = case_rew_data[case_rew_data['Distance'] >= self.prediction_period]

        #Temporal windows creation
        for windowNum in range(casePositive + caseNegative):
            min, max = self.prediction_period + self.overlap_size* windowNum, self.prediction_period + self.overlap_size* windowNum + self.window_size
            if self.overlap_size ==0:
                min, max = self.prediction_period + self.window_size * windowNum, self.prediction_period + self.window_size * (windowNum +1)
            window = case_rew_data[(case_rew_data['Distance'] >= min) & (case_rew_data['Distance'] < max)]
            window.reset_index(inplace=True, drop=True)
            window = self.resetWindowTimeStamp(window)
            currEntitiesMapping = self.createWindowEntityMapping(window)

            # add the class of each new entity to entityClassDf -> the class of the first casePositive windows is 1
            newEntitiesClass = currEntitiesMapping[['EntityID']].copy()
            if windowNum < casePositive:
                newEntitiesClass['ClassID'] = 1
            else:
                newEntitiesClass['ClassID'] = 0
            self.EntitiesClassDf = self.EntitiesClassDf.append(newEntitiesClass)
            self.updateEntityIdInWindowDf(currEntitiesMapping, window)

    def createWindowEntityMapping(self, window):
        """
       This method set for each windoe a new ID and save the  mapping of the new-old entity id in the EntitiesMapping df.
       run on the x window of all the case/control entities together
       :return: currEntitiesMapping
       """
        # add mapping of the new-old entity id
        currEntitiesMapping = window[['EntityID']].copy()
        currEntitiesMapping = currEntitiesMapping.drop_duplicates()
        currEntitiesMapping.reset_index(inplace=True, drop=True)
        currEntitiesMapping = currEntitiesMapping.rename(columns={"EntityID": "OriginalEntityID"})
        self.EntitiesCounter = 0
        currEntitiesMapping['EntityID'] = np.arange(self.EntitiesCounter, len(currEntitiesMapping) + self.EntitiesCounter)
        self.EntitiesCounter = currEntitiesMapping['EntityID'].max() + 1
        self.EntitiesMapping = self.EntitiesMapping.append(currEntitiesMapping)
        return currEntitiesMapping

    def updateEntityIdInWindowDf(self, currEntitiesMapping, window):
        """
          This method
          :return: None
          """
        window = window.rename(columns={"EntityID": "OriginalEntityID"})
        new_window = pd.merge(window, currEntitiesMapping, on="OriginalEntityID")
        new_window = new_window[['EntityID', 'TemporalPropertyID', 'TemporalPropertyValue','TimeStamp', 'Outcome_TS','Distance']].copy()
        self.windowsTemporalDataDF = self.windowsTemporalDataDF.append(new_window)

    def resetWindowTimeStamp(self, window):
        """
       This method reset the window time stemp ->each window will strat at timestamp 0
       with maximum timestamp value of window_size
       :return: new_window -> the update window df
       """
        columns = ['EntityID', 'TemporalPropertyID', 'TemporalPropertyValue', 'TimeStamp', 'Outcome_TS','Distance']
        new_window = pd.DataFrame(columns=columns)
        Entities = window.EntityID.unique()
        for Entity in Entities:
            Entity_df = window[window['EntityID'] == Entity]
            # taking only windows with more then window_size*2 rows (threshold)
            if len(Entity_df) > (self.window_size*2):
                min_timeStemp = Entity_df['TimeStamp'].min()
                max_timeStemp = Entity_df['TimeStamp'].max()
                TimeStamp = np.arange(min_timeStemp, max_timeStemp + 1)
                window_TimeStamp = pd.DataFrame({'TimeStamp': TimeStamp})
                window_TimeStamp['New_TimeStamp'] = np.arange(len(window_TimeStamp))
                window_TimeStamp = pd.merge(Entity_df, window_TimeStamp, on="TimeStamp")
                window_TimeStamp = window_TimeStamp.drop(['TimeStamp'], axis=1)
                window_TimeStamp = window_TimeStamp.rename(columns={"New_TimeStamp": "TimeStamp"})
                new_window = new_window.append(window_TimeStamp)
        return new_window

    def create_Control_Windows(self, windowsAmount):
        EntitiesIDs = self.EntitiesClass.loc[self.EntitiesClass['Class'] == 0]
        control_rew_data = self.rew_data.loc[self.rew_data['EntityID'].isin(EntitiesIDs.EntityID.unique()), :].copy()
        control_rew_data.reset_index(inplace=True, drop=True)

        # choose for each control entity outcome timestamp- randomly/maximum/KB(additional csv needed)
        controlOutcomeTimeStemp = self.creatControlOutcomeDF()

        # Add outcome and distance columns to the df
        OutcomeTS = controlOutcomeTimeStemp[['EntityID', 'TimeStamp']].copy()
        OutcomeTS = OutcomeTS.rename(columns={"TimeStamp": "Outcome_TS"})
        control_rew_data = pd.merge(control_rew_data, OutcomeTS, on="EntityID")
        control_rew_data['Distance'] = control_rew_data['Outcome_TS'] - control_rew_data['TimeStamp']

        # Remove the rows with timestamp after the outcomeTS or from the prediction period
        control_rew_data = control_rew_data[control_rew_data['Distance'] >= self.prediction_period]

        for windowNum in range(windowsAmount):
            min, max = self.prediction_period + self.overlap_size * windowNum, self.prediction_period + self.overlap_size * windowNum + self.window_size
            if self.overlap_size == 0:
                min, max = self.prediction_period + self.window_size * windowNum, self.prediction_period + self.window_size * (windowNum + 1)
            window = control_rew_data[(control_rew_data['Distance'] >= min) & (control_rew_data['Distance'] < max)]
            window.reset_index(inplace=True, drop=True)
            window = self.resetWindowTimeStamp(window)
            currEntitiesMapping = self.createWindowEntityMapping(window)
            # add the class of each new entity to entityClassDf
            newEntitiesClass = currEntitiesMapping[['EntityID']].copy()
            newEntitiesClass['ClassID'] = 0
            self.EntitiesClassDf = self.EntitiesClassDf.append(newEntitiesClass)
            self.updateEntityIdInWindowDf(currEntitiesMapping, window)

    def creatControlOutcomeDF(self):
        """
          This method choose for each control entity outcome timestamp by one of the two methods - randomly/KB.
          KB - if the raw data contain TemporalPropertyID = -4/-3.
          if contain TemporalPropertyID = -4 it will define the outcome timestamp, if not but
          the raw data contain TemporalPropertyID = -3 it will define the outcome timestamp otherwise, it will be set randomly
          return: controlOutcomeTimeStemp, df with the folowing format: ['EntityID', 'TimeStamp']
         """
        #************TO DO*************
        self.controlOutcomeTimeStemp = pd.DataFrame(columns=['EntityID', 'TimeStamp'])
        if (self.rew_data['TemporalPropertyID'] == -4).any() or (self.rew_data['TemporalPropertyID'] == -3).any():
            if (self.rew_data['TemporalPropertyID'] == -4).any():
                df = self.rew_data.loc[self.rew_data['TemporalPropertyID'] == -4]
                self.controlOutcomeTimeStemp = df[['EntityID', 'TimeStamp']].copy()
            else:
                df = self.rew_data.loc[self.rew_data['TemporalPropertyID'] == -3]
                self.controlOutcomeTimeStemp = df[['EntityID', 'TimeStamp']].copy()
        else:
            count = 0
            for e in self.EntitiesClass['EntityID'] :
                df = self.rew_data.loc[self.rew_data['EntityID'] == e]
                df = df.loc[df['TemporalPropertyID'] != -1]
                if len(df) > 0 :
                    val = df.sample()['TimeStamp'].values[0]
                    listOfSeries = [ pd.Series([e, val], index= self.controlOutcomeTimeStemp.columns)]
                    self.controlOutcomeTimeStemp = self.controlOutcomeTimeStemp.append(listOfSeries, ignore_index=True)
        self.controlOutcomeTimeStemp.to_csv(self.output_path + "/controlOutcomeTimeStemp.csv")
        return self.controlOutcomeTimeStemp
    def writeDfToPickelTemporalEtities(self, path):
        """
          This method
           return: None
         """

        #self.EntitiesMapping.to_pickle(self.output_path + "/" + self.experimentName + "_" + self.StudyDesign + "/EntitiesMapping.pkl")
        #self.EntitiesClassDf.to_pickle(self.output_path +"/" + self.experimentName+"_"+self.StudyDesign +  "/EntitiesClassDf.pkl")

        #add the new class to the new temporal windows raw data df -> windowsTemporalDataDF
        self.EntitiesClassDf['TimeStamp'] = 0
        self.EntitiesClassDf['TemporalPropertyID'] = -1
        self.EntitiesClassDf = self.EntitiesClassDf.rename(columns={"ClassID": "TemporalPropertyValue"})


        windowsTemporalDataDF = self.windowsTemporalDataDF[['EntityID', 'TemporalPropertyID', 'TimeStamp', 'TemporalPropertyValue']].copy()
        windowsTemporalDataDF = windowsTemporalDataDF.append(self.EntitiesClassDf)

        windowsTemporalDataDF.to_csv(self.output_path + "/window.csv")
        #windowsTemporalDataDF.to_csv(self.output_path + "/" + self.experimentName+"_"+self.StudyDesign + "/windowsTemporalDataDF.csv")
        self.EntitiesClassDf.to_csv(self.output_path  + "/entity_class_relations.csv")

        self.getSampleDf(windowsTemporalDataDF)
        #self.getSampleDf(windowsTemporalDataDF)

    def getSampleDf(self, windowsTemporalDataDF):
        """
          This method set the classification df by the given ration foe the experiment.
          there are to option for choosing the positive and negative windows:
          data volum - choose the bigest X windows
          randomn (**TO DO**)
          return: None
         """
        positive_entities = self.EntitiesClassDf[self.EntitiesClassDf['TemporalPropertyValue'] == 1]
        positive_entities = positive_entities[['EntityID']].copy()

        Ratio = self.positiveNegativeRatio[1]/self.positiveNegativeRatio[0]
        positive_number = len(positive_entities.EntityID.unique())
        negative_number = positive_number * Ratio

        negative_entities = self.EntitiesClassDf[self.EntitiesClassDf['TemporalPropertyValue'] == 0]
        total_negative_number = len(negative_entities.EntityID.unique())



        if(self.ChoiceType == "volum"):
            #creat df with positive windows data only
            positive_windows = windowsTemporalDataDF.loc[windowsTemporalDataDF['EntityID'].isin(positive_entities['EntityID'].tolist())]
            # add column of 'Window_Size' and inialized it to zero
            positive_windows.loc['Window_Size'] = 0

            #update the Window_Size column value for each positive window
            #*!*could be done more efficiently by executing group by with count for each id*!*
            for e in positive_windows.EntityID.unique():
                temp = windowsTemporalDataDF.loc[windowsTemporalDataDF['EntityID'] == e]
                indexs = temp.index.tolist()
                positive_windows.loc[indexs, 'Window_Size'] = len(indexs)
            positive_windows_id = positive_windows[['EntityID','Window_Size']].copy()
            positive_windows_id = positive_windows_id.drop_duplicates()
            positive_windows_id = positive_windows_id.sort_values(by=['Window_Size'])
            positive_windows_id = positive_windows_id.tail(positive_number)
            positive_windows = windowsTemporalDataDF.loc[windowsTemporalDataDF['EntityID'].isin(positive_windows_id.EntityID.unique())]

            negative_entities = self.EntitiesClassDf[self.EntitiesClassDf['TemporalPropertyValue'] == 0]
            print(len(negative_entities.EntityID.unique()))
            negative_windows = windowsTemporalDataDF.loc[windowsTemporalDataDF['EntityID'].isin(negative_entities.EntityID.unique())]
            negative_windows['Window_Size'] = 0

            # update the Window_Size column value for each negative window
            # *!*could be done more efficiently by executing group by with count for each id*!*
            for e in negative_windows.EntityID.unique():
                temp = windowsTemporalDataDF.loc[windowsTemporalDataDF['EntityID'] == e]
                indexs = temp.index.tolist()
                negative_windows.loc[indexs, 'Window_Size'] = len(indexs)
            negative_windows_id = negative_windows[['EntityID', 'Window_Size']].copy()
            negative_windows_id = negative_windows_id.drop_duplicates()
            negative_windows_id = negative_windows_id.sort_values(by=['Window_Size'])
            negative_windows_id = negative_windows_id.tail(negative_number)
            negative_windows = windowsTemporalDataDF.loc[windowsTemporalDataDF['EntityID'].isin(negative_windows_id.EntityID.unique())]
        else:
            negative_number = round(negative_number)
            l = [random.randint(0, total_negative_number) for i in range(negative_number)]
            negative_windows = windowsTemporalDataDF.loc[windowsTemporalDataDF['EntityID'].isin(l)]
            positive_windows = windowsTemporalDataDF.loc[windowsTemporalDataDF['EntityID'].isin(positive_entities['EntityID'].tolist())]



        sample_df = positive_windows.append(negative_windows)
        #sample_df.to_csv(self.output_path + "/" + self.experimentName+"_"+self.StudyDesign + "/sampleDf.csv")
        sample_df.to_csv(self.output_path + "/sampleDf.csv")

















