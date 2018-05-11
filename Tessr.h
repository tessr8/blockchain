#ifndef TessrChain_H
#define TessrChain_H
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#define DNG_SIZE		        256
#define DNG_NOTSET		        -1
#define DNG_VALUENOTUSED	    0
#define DNG_VALUEUSED		    1
#define DNG_STATE_NOTCONNECTED	0
#define DNG_STATE_CONNECTED	1

namespace TessrChain
{
	typedef unsigned char byte;
	typedef unsigned long ulong;
	class TessrChain
	{
	private:
		byte State;						//Main state
		short DNG[DNG_SIZE];			//Main memory encryption key
		ulong DNGVersion;			    //DNG Changes
		byte UsedValuesMap[DNG_SIZE];	//Map of used values in DNG
		short FilledCells;				//Count of correctly filled cells in DNG
		short DNGOne;					//Swap
		short DNGAll[DNG_SIZE];			//Swap array AND reverse array
		byte RoundCount;				//How many rounds of encryption of a message to do
		float ProbToGenKey;				//Probability to generate a Key (but not a Value) to next round
		float ProbDecay;				//Probability decay rate
		short Key;						//Last Key
		short Value;					//Last Value
		short ToSend;					//Key or Value to Send
		char DNGString[DNG_SIZE * 6];	//Stringed version of DNG
	    int ExtraRand;                  //Extra randomization variable
	    char LogFileName[256];          //If set, logs out all activity
	    bool isLogging;                 //logs

	public:
// ----------------------------------------------------------------------------------------
//	Init and configure
// ----------------------------------------------------------------------------------------

		TessrChain(void)
		{
		    isLogging = false;
		    ProbDecay = 2.0;
		    RoundCount = 16;
			Reset();
		}

		void SetLogging(const char* FileName)
		{
		    strcpy(LogFileName, FileName);
		    isLogging = true;
		}
// ----------------------------------------------------------------------------------------
//  Sets (default) encryption/decryption round count.
// ----------------------------------------------------------------------------------------
		bool SetRoundsCount(byte iRoundCount)
		{
			if(State == DNG_STATE_NOTCONNECTED)
			{
				RoundCount = iRoundCount;
				return true;
			}
			return false;
		}
// ----------------------------------------------------------------------------------------
//	Sets (default) decay of pointer selection probability. 
// ----------------------------------------------------------------------------------------
		bool SetProbDecay(float fProbDecay)
		{
			if(State == DNG_STATE_NOTCONNECTED)
			{
				ProbDecay = fProbDecay;
				return true;
			}
			return false;
		}
// ----------------------------------------------------------------------------------------
//	Simulates an primitive (unsafe) connection
// ----------------------------------------------------------------------------------------
		void SimulateConnection(void)
		{
		    State = DNG_STATE_CONNECTED;
			for(short c = 0; c < DNG_SIZE; c++)
			{
				DNG[(11 * c) % DNG_SIZE] = c;
				UsedValuesMap[c] = DNG_VALUEUSED;
			}
			FilledCells = DNG_SIZE;
			DNGVersion = DNG_SIZE + 1;
			GetDNG();
		}
// ----------------------------------------------------------------------------------------
//	Gets stringed version of DNG (DEBUG)
// ----------------------------------------------------------------------------------------
		const char* GetDNG(void)
		{
			char ValTmp[8];
			memset(DNGString, 0, DNG_SIZE * 6 * sizeof(char));
			for(short c = 0; c < DNG_SIZE; c++)
			{
                if(DNG[c] == DNG_NOTSET)
                    sprintf(ValTmp, (c ? " _": "_"));
                else
                    sprintf(ValTmp, (c ? " %i": "%i"), DNG[c]);
				strcat(DNGString, ValTmp);
			}
			return static_cast<const char*>(DNGString);
		}

// ----------------------------------------------------------------------------------------
//	Encryption
// ----------------------------------------------------------------------------------------

		void sE(const ulong Length, byte* Message) const
		
			if(Length && Message && (State == DNG_STATE_CONNECTED))
			{
				ulong p, Offset;

				for(int r = 0; r < RoundCount; r++)
				{
					Offset = 1;
					for(p = 0; p < Length; p++)
					{
						Message[p] = (DNG_SIZE-1) - Message[p];
						Message[p] = (Message[p] + DNG[p % DNG_SIZE]) % DNG_SIZE;
						Message[p] = DNG[Message[p] % DNG_SIZE];
						Offset += Message[p];
					}
					if(Offset)
					{
						Shift(Message, Length, Offset);
					}
				}
			}
		}

// ----------------------------------------------------------------------------------------
//	Decryption
// ----------------------------------------------------------------------------------------

		void sD(const ulong Length, byte* Message)
		{
			if(Length && Message && (State == DNG_STATE_CONNECTED))
			{
				ulong p, Offset;
				for(short c = 0; c < DNG_SIZE; c++)
				{
				    if((0 <= DNG[c]) && (DNG[c] < DNG_SIZE))
					DNGAll[DNG[c]] = c;
				}

				for(int r = 0; r < RoundCount; r++)
				{
					Offset = 1;
					for(p = 0; p < Length; p++)
						Offset += Message[p];
					if(Offset)
					{
						Shift(Message, Length, -Offset);
					}

					for(p = 0; p < Length; p++)
					{			
						Message[p] = DNGAll[Message[p] % DNG_SIZE];
						Message[p] = (Message[p] + DNG_SIZE - DNG[p % DNG_SIZE]) % DNG_SIZE;
						Message[p] = (DNG_SIZE-1) - Message[p];
					}
				}
			}
		}

// ----------------------------------------------------------------------------------------
//	Connection
// ----------------------------------------------------------------------------------------

		void GenKV(void)
		{
			if(State == DNG_STATE_NOTCONNECTED)
			{
				bool Connected = false;
				if(Random() < ProbToGenKey)
				{
					
// ----------------------------------------------------------------------------------------				
//	Gen a Key, listen for a Value. We have to select a random unused Key
// ----------------------------------------------------------------------------------------

					int RandomKey = PickRandomElementFromArrayByFilterEQ(DNG, DNG_SIZE, DNG_NOTSET);
					if(RandomKey != -1)
					{
						Key = RandomKey;
						ToSend = Key;
						ToLog("%s -> {%i _}\n", GetDNG(), ToSend);
					}
					else
					{
						Key = DNG_NOTSET;				
						Connected = true;
					}
					Value = DNG_NOTSET;
				}
				else
				{
// ----------------------------------------------------------------------------------------
//	Gen a Value, listen for a Key. We have to select a random unused Value
// ----------------------------------------------------------------------------------------
					int RandomValue = PickRandomElementFromArrayByFilterEQ(UsedValuesMap, DNG_SIZE, DNG_VALUENOTUSED);
					if(RandomValue != -1)
					{
						Value = RandomValue;
						ToSend = Value;
						ToLog("%s -> {_ %i}\n", GetDNG(), ToSend);
					}
					else
					{
						Value = DNG_NOTSET;
						Connected = true;
					}
					Key = DNG_NOTSET;
				}
				if(Connected)
				{
					State = DNG_STATE_CONNECTED;
					ToSend = DNG_NOTSET;
					ToLog("%s Connected!\n", GetDNG());
				}
			}
		}
		short GetKV(void) const
		{
			return ToSend;
		}
		void ProcessKV(const short KV)
		{
			if(State == DNG_STATE_NOTCONNECTED)
			{
                ToLog("Incoming {%i}\n", KV);

				if(KV == DNG_NOTSET)
				{
					Reset();
					return;
				}

				bool KeyThisTime = false;

				if(Value == DNG_NOTSET)
				{
					Value = KV;
					KeyThisTime = true;
				}
				if(Key == DNG_NOTSET)
				{
					Key = KV;
					KeyThisTime = false;
				}

			    ToLog("%s + {%i %i} = ", GetDNG(), Key, Value);
				if((DNG[Key] == DNG_NOTSET) && (UsedValuesMap[Value] == DNG_VALUENOTUSED))
				{
					DNG[Key] = Value;
					UsedValuesMap[Value] = DNG_VALUEUSED;
					FilledCells++;
					if(KeyThisTime)
					{
						ProbToGenKey = ProbToGenKey / (ProbDecay + static_cast<float>(Value % 2));
					}
					else
					{
						ProbToGenKey = 1.0 - ((1.0 - ProbToGenKey) / (ProbDecay + static_cast<float>(Value % 2)));
					}

					ToLog("%s\nFilled Cells: %i, Key Probability: %f\n", GetDNG(), FilledCells, ProbToGenKey);
				}
				else
				{
					ToLog("Collision!\n");
					Reset();
				}
			}
		}
		int Test(void)
		{
		    int TestResult = TestAll();
		    ToLog("Test Result: %i\n", TestResult);
		    return TestResult;
		}


	private:
// ----------------------------------------------------------------------------------------
//	Deleted functions
// ----------------------------------------------------------------------------------------

		TessrChain(const TessrChain& rhs);		
		TessrChain& operator=(const TessrChain& rhs);	

// ----------------------------------------------------------------------------------------
//	Init and configure
// ----------------------------------------------------------------------------------------

		void Reset(void)
		{
			srand(time(NULL) + ExtraRand);
			ExtraRand += Random(333, 777);
			ToLog("Resetting!\n");

			for(short c = 0; c < DNG_SIZE; c++)
			{
				DNG[c] = DNG_NOTSET;
				DNGAll[c] = DNG_NOTSET;
				UsedValuesMap[c] = DNG_VALUENOTUSED;
			}
			FilledCells = 0;

			State = DNG_STATE_NOTCONNECTED;

			DNGVersion = 0;

			ProbToGenKey = 0.5;

			Key = DNG_NOTSET;
			Value = DNG_NOTSET;
			ToSend = DNG_NOTSET;
		}

// ----------------------------------------------------------------------------------------
//	Changing DNG
// ----------------------------------------------------------------------------------------

		void DeltaAB(const byte A, const byte B)
		{
			if(A != B)
			{
				DNGOne = DNG[A];
				DNG[A] = DNG[B];
				DNG[B] = DNGOne;
			}
		}

		void DeltaM(const byte M)
		{
			Shift(DNG, DNG_SIZE, M);
		}

		void Delta(void)
		{
			for(short c = 0; c < DNG_SIZE; c++)
			{
			    if((0 <= DNG[c]) && (DNG[c] < DNG_SIZE))
                {
                    DNGAll[c] = DNG[DNG[c]];
                }
			}
			memcpy(DNG, DNGAll, DNG_SIZE * sizeof(short));
		}

		void Omega(const byte A, const byte B, const byte M)
		{
			DeltaAB(A, B);
			DeltaM(M);
			Delta();
		}
		void sS(const ulong Length, const byte* Message)
		{
			if(Length && Message)
			{
				byte i, j;
				for(i = 0; i < 64; i++)
				{
					for(j = i + 1; j < 128; j++)
					{
						Omega(j, (j * j * j) % DNG_SIZE, Message[i % Length]);
						Omega(DNG_SIZE-1 - j, (j * j) % DNG_SIZE, Message[Length / 2]);
						Omega(Message[i % Length], Message[j % Length], (i + j) % DNG_SIZE);
					}
				}
				DNGVersion++;
			}
		}

// ----------------------------------------------------------------------------------------
//	Utils
// ----------------------------------------------------------------------------------------

		template<typename T>
		void Shift(T* Data, const ulong& Length, long Offset) const
		{
            if((!Data) || (!Length))
                return;

            if(Offset < 0)
                Offset = (Length-1) - ((-Offset-1) % Length);
            else
                Offset %= Length;

            if(!Offset)
                return;

            int TSize = sizeof(T);

			T* Shifter = new T[Length];

			if(Shifter)
            {
                memcpy(Shifter, Data + Offset, TSize * (Length - Offset));
                memcpy(Shifter + (Length - Offset), Data, TSize * Offset);
                memcpy(Data, Shifter, TSize * Length);

                delete[] Shifter;
            }
		}
// ----------------------------------------------------------------------------------------
//Picks a random element from array Data of length.
// ----------------------------------------------------------------------------------------
		template<typename T1, typename T2>
		int PickRandomElementFromArrayByFilterEQ(const T1* Data, const int DataLength, const T2 Filter) const
		{
			int RandomPointer = Random(0, DataLength - 1);
			int EndPoint = RandomPointer;
			while(true)
			{
				if(Data[RandomPointer] == Filter)
					return RandomPointer;
				RandomPointer = (RandomPointer + 1) % DataLength;
				if(RandomPointer == EndPoint)
					break;
			}
			return -1;
		}
		float Random(void) const
		{
			return (rand() % 32768) / 32767.0;
		}
		const int Random(const int A, const int B) const
		{
			return A + Random() * (float)(B - A);
		}

		byte GetState(void) const
		{
			return State;
		}

		ulong GetDNGVersion() const
		{
			return DNGVersion;
		}

		void ToLog(const char* Format, ...) const
		{
            if(isLogging)
            {
                FILE* LogFile = fopen(LogFileName, "a+");
                if(LogFile)
                {
                    va_list args;
                    va_start(args, Format);
                    vfprintf(LogFile, Format, args);
                    va_end(args);

                    fflush(LogFile);
                    fclose(LogFile);
                }
            }
		}

// ----------------------------------------------------------------------------------------
//	Tests
// ----------------------------------------------------------------------------------------
		int TestAll(void) 
		{
            if(!TestEstCon()) return -1;
            if(!TestExch()) return -2;
		    return 0;
		}

		bool TestEstCon(void)   
		{
			int SameDNGCount = 0;
			int NotSameDNGCount = 0;

			for(int iTest = 0; iTest < 100; iTest++)    
            {
                TessrChain TessrChainAlice;
                TessrChain TessrChainBob;

                TessrChainAlice.SetProbDecay(1000);            
                TessrChainBob.SetProbDecay(1000);           

                while((TessrChainAlice.GetState() == DNG_STATE_NOTCONNECTED) || (TessrChainBob.GetState() == DNG_STATE_NOTCONNECTED))
                {
                    TessrChainAlice.GenKV();
                    TessrChainBob.GenKV();
                    TessrChainAlice.ProcessKV(TessrChainBob.GetKV());
                    TessrChainBob.ProcessKV(TessrChainAlice.GetKV());
                }

                if(strcmp(TessrChainAlice.GetDNG(), TessrChainBob.GetDNG()) == 0)
                    SameDNGCount++;
                else
                    NotSameDNGCount++;
            }
            return (SameDNGCount * 2 > NotSameDNGCount);
		}

		bool TestExch(void)
		{
			bool bTestIsOK = true;

            TessrChain TessrChainAlice;
            TessrChain TessrChainBob;

            TessrChainAlice.SetRoundsCount(8);
            TessrChainBob.SetRoundsCount(8);
            TessrChainAlice.SimulateConnection();
            TessrChainBob.SimulateConnection();

            if(isLogging)
            {
                TessrChainAlice.SetLogging("./AliceLog.txt");
                TessrChainBob.SetLogging("./BobLog.txt");
            }

			ulong uMessageLen;
			byte* pbOriginalMessage;
			byte* pbMessage;
			TessrChain* pTessrChainSender;
			TessrChain* pTessrChainreceiver;
			for(int iTest = 0; iTest < 100; iTest++) 
			{
				uMessageLen = Random(100, 200);
				pbMessage = new byte[uMessageLen];
				if(pbMessage)
                {
                    memset(pbMessage, 0, uMessageLen * sizeof(byte));
                    for(ulong uChar = 0; uChar < uMessageLen; uChar++)
                        pbMessage[uChar] = Random(0, DNG_SIZE - 1);
                    pbOriginalMessage = new byte[uMessageLen];
                    if(pbOriginalMessage)
                    {
                        memcpy(pbOriginalMessage, pbMessage, uMessageLen * sizeof(byte));
                        if(Random() < .5)
                        {
                            pTessrChainSender = &TessrChainAlice;
                            pTessrChainreceiver = &TessrChainBob;
                        }
                        else
                        {
                            pTessrChainreceiver = &TessrChainAlice;
                            pTessrChainSender = &TessrChainBob;
                        }
                        pTessrChainSender->sE(uMessageLen, pbMessage);
                        pTessrChainSender->sS(uMessageLen, pbOriginalMessage);
                        pTessrChainreceiver->sD(uMessageLen, pbMessage);
                        pTessrChainreceiver->sS(uMessageLen, pbMessage);
                        if(memcmp(pbOriginalMessage, pbMessage, uMessageLen * sizeof(byte)))
                            bTestIsOK = false;
                        delete [] pbOriginalMessage;
                        delete [] pbMessage;
                        if(!bTestIsOK)
                            return false;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
			}
			return true;
		}
	};
}

#endif
