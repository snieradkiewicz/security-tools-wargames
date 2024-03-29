class Assets:
    def __init__(self):
        self.instance_nr = 0

    english_letter_frequency = {'E': 0.1202,
                                'T': 0.091,
                                'A': 0.0812,
                                'O': 0.0768,
                                'I': 0.0731,
                                'N': 0.0695,
                                'S': 0.0628,
                                'R': 0.0602,
                                'H': 0.0592,
                                'D': 0.0432,
                                'L': 0.0398,
                                'U': 0.0288,
                                'C': 0.0271,
                                'M': 0.0261,
                                'F': 0.023,
                                'Y': 0.0211,
                                'W': 0.0209,
                                'G': 0.0203,
                                'P': 0.0182,
                                'B': 0.0149,
                                'V': 0.0111,
                                'K': 0.0069,
                                'X': 0.0017,
                                'Q': 0.0011,
                                'J': 0.001,
                                'Z': 0.0007}
    english_letters_and_words_frequency = {'THE ': 50,
                                           'BE ': 45,
                                           'TO ': 40,
                                           'OF ': 35,
                                           'AND ': 30,
                                           'IN ': 25,
                                           'THAT ': 20,
                                           'HAVE ': 15,
                                           'IT ': 10,
                                           'E': 12.02,
                                           'T': 9.1,
                                           'A': 8.12,
                                           'O': 7.68,
                                           'I': 7.31,
                                           'N': 6.95,
                                           'S': 6.28,
                                           'R': 6.02,
                                           'H': 5.92,
                                           'D': 4.32,
                                           'L': 3.98,
                                           'U': 2.88,
                                           'C': 2.71,
                                           'M': 2.61,
                                           'F': 2.3,
                                           'Y': 2.11,
                                           'W': 2.09,
                                           'G': 2.03,
                                           'P': 1.82,
                                           'B': 1.49,
                                           'V': 1.11,
                                           'K': 0.69,
                                           'X': 0.17,
                                           'Q': 0.11,
                                           'J': 0.1,
                                           'Z': 0.07,
                                           '.': 0.05,
                                           ',': 0.05,
                                           '\'': 0.05,
                                           '!': 0.05,
                                           '?': 0.05}
    english_letter_by_freq = bytearray(b'ETAOINSRHDLUCMFYWGPBVKXQJZ')
    english_words_frequency = {'THE': 200,
                               'OF': 199,
                               'AND': 198,
                               'TO': 197,
                               'IN': 196,
                               'IS': 195,
                               'BE': 194,
                               'THAT': 193,
                               'WAS': 192,
                               'HE': 191,
                               'FOR': 190,
                               'IT': 189,
                               'WITH': 188,
                               'AS': 187,
                               'HIS': 186,
                               'ON': 185,
                               'HAVE': 184,
                               'AT': 183,
                               'BY': 182,
                               'NOT': 181,
                               'THEY': 180,
                               'THIS': 179,
                               'HAD': 178,
                               'ARE': 177,
                               'BUT': 176,
                               'FROM': 175,
                               'OR': 174,
                               'SHE': 173,
                               'AN': 172,
                               'WHICH': 171,
                               'YOU': 170,
                               'ONE': 169,
                               'WE': 168,
                               'ALL': 167,
                               'WERE': 166,
                               'HER': 165,
                               'WOULD': 164,
                               'THERE': 163,
                               'THEIR': 162,
                               'WILL': 161,
                               'WHEN': 160,
                               'WHO': 159,
                               'HIM': 158,
                               'BEEN': 157,
                               'HAS': 156,
                               'MORE': 155,
                               'IF': 154,
                               'NO': 153,
                               'OUT': 152,
                               'DO': 151,
                               'SO': 150,
                               'CAN': 149,
                               'WHAT': 148,
                               'UP': 147,
                               'SAID': 146,
                               'ABOUT': 145,
                               'OTHER': 144,
                               'INTO': 143,
                               'THAN': 142,
                               'ITS': 141,
                               'TIME': 140,
                               'ONLY': 139,
                               'COULD': 138,
                               'NEW': 137,
                               'THEM': 136,
                               'MAN': 135,
                               'SOME': 134,
                               'THESE': 133,
                               'THEN': 132,
                               'TWO': 131,
                               'FIRST': 130,
                               'MAY': 129,
                               'ANY': 128,
                               'LIKE': 127,
                               'NOW': 126,
                               'MY': 125,
                               'SUCH': 124,
                               'MAKE': 123,
                               'OVER': 122,
                               'OUR': 121,
                               'EVEN': 120,
                               'MOST': 119,
                               'ME': 118,
                               'STATE': 117,
                               'AFTER': 116,
                               'ALSO': 115,
                               'MADE': 114,
                               'MANY': 113,
                               'DID': 112,
                               'MUST': 111,
                               'BEFORE': 110,
                               'BACK': 109,
                               'SEE': 108,
                               'THROUGH': 107,
                               'WAY': 106,
                               'WHERE': 105,
                               'GET': 104,
                               'MUCH': 103,
                               'GO': 102,
                               'WELL': 101,
                               'YOUR': 100,
                               'KNOW': 99,
                               'SHOULD': 98,
                               'DOWN': 97,
                               'WORK': 96,
                               'YEAR': 95,
                               'BECAUSE': 94,
                               'COME': 93,
                               'PEOPLE': 92}
