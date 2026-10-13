unit Hash64Tests;

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  HashLibTestBase,
  HlpIHashInfo,
  HlpHashFactory;

// Hash64

type
  TTestFNV64 = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestFNV1a64 = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestMurmur2_64 = class(THashWithUInt64AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSipHash2_4 = class(THashWithExternalKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestXXHash64 = class(THashWithUInt64AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestXXHash3 = class(THashWithUInt64AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    // Known-answer tests for the long-input paths (values cross-checked
    // against the official xxHash implementation): the self-consistency
    // chunked tests alone cannot catch a wrong SIMD kernel because both
    // sides run the same code.
    procedure TestChunkedDataKnownAnswer;          // 299 bytes: accumulate512
    procedure TestTwoKiBDataKnownAnswer;           // 2048 bytes: scrambleAcc
    procedure TestChunkedDataWithMaxUInt64AsKeyKnownAnswer; // seeded: initSecret
    // An asymmetric key (lo32 <> hi32) - a symmetric one like MaxUInt64
    // cannot catch seed dword swaps or wrong hi/lo pickup in the kernels.
    procedure TestChunkedDataWithAsymmetricKeyKnownAnswer;

  end;


type
  // Base for 64-bit hashes verified against an external reference over a
  // range of input lengths chosen to reach every code path. The input of
  // length N is the bytes 0, 1, 2, ... (N - 1) (each modulo 256).
  THash64LengthKnownAnswerTestCase = class abstract
    (THashWithUInt64AsKeyAlgorithmTestCase)
  strict protected
  const
    KnownAnswerLengths: array [0 .. 26] of Int32 = (0, 1, 3, 4, 7, 8, 16, 17,
      32, 33, 48, 49, 64, 80, 81, 96, 97, 112, 113, 128, 129, 200, 224, 256,
      257, 300, 1000);
  var
    FLengthKnownAnswers: array [0 .. 26] of String;
    FHashOf1000BytesWithAsymmetricKey: String;

    class function MakeData(ALength: Int32): TBytes; static;

  published
    // one-shot and incremental (odd-sized chunks) hashing of each length
    procedure TestLengthKnownAnswers;
    // key = $0123456789ABCDEF over the 1000-byte input
    procedure Test1000BytesWithAsymmetricKeyKnownAnswer;

  end;

type

  TTestRapidHash = class(THash64LengthKnownAnswerTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestRapidHashMicro = class(THash64LengthKnownAnswerTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestRapidHashNano = class(THash64LengthKnownAnswerTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestFoldHash = class(THash64LengthKnownAnswerTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestFoldHashQuality = class(THash64LengthKnownAnswerTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

implementation

// Hash64

{ TTestFNV64 }

procedure TTestFNV64.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateFNV();
  HashOfEmptyData := '0000000000000000';
  HashOfDefaultData := '061A6856F5925B83';
  HashOfOnetoNine := 'B8FB573C21FE68F1';
  HashOfABCDE := '77018B280326F529';
end;

procedure TTestFNV64.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestFNV1a64 }

procedure TTestFNV1a64.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateFNV1a();
  HashOfEmptyData := 'CBF29CE484222325';
  HashOfDefaultData := '5997E22BF92B0598';
  HashOfOnetoNine := '06D5573923C6CDFC';
  HashOfABCDE := '6348C52D762364A8';
end;

procedure TTestFNV1a64.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestMurmur2_64 }

procedure TTestMurmur2_64.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateMurmur2();
  HashOfEmptyData := '0000000000000000';
  HashOfDefaultData := '831EFD69DC9E99F9';
  HashOfOnetoNine := '4977490251674330';
  HashOfABCDE := '1182974836D6DBB7';
  HashOfDefaultDataWithMaxUInt64AsKey := 'FF0A342F0AF9ADC6';
end;

procedure TTestMurmur2_64.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestSipHash2_4 }

procedure TTestSipHash2_4.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateSipHash2_4();
  HashOfEmptyData := '310E0EDD47DB6F72';
  HashOfDefaultData := '4ED2198628C443AA';
  HashOfOnetoNine := 'FDFE0E0296FC60CA';
  HashOfABCDE := '73B879EAE16345A7';
  HashOfDefaultDataWithExternalKey := '4ED2198628C443AA';
end;

procedure TTestSipHash2_4.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestXXHash64 }

procedure TTestXXHash64.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateXXHash64();
  HashOfEmptyData := 'EF46DB3751D8E999';
  HashOfDefaultData := '0F1FADEDD0B77861';
  HashOfOnetoNine := '8CB841DB40E6AE83';
  HashOfABCDE := '07E3670C0C8DC7EB';
  HashOfDefaultDataWithMaxUInt64AsKey := '68DCC1056096A94F';
end;

procedure TTestXXHash64.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestXXHash3 }

procedure TTestXXHash3.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateXXHash3();
  HashOfEmptyData := '2D06800538D394C2';
  HashOfDefaultData := '73B9276A6BAC2B49';
  HashOfOnetoNine := '72DCB18B67A17DFF';
  HashOfABCDE := '55C65158EE9E652D';
  HashOfDefaultDataWithMaxUInt64AsKey := '153E26503A9470AF';
end;

procedure TTestXXHash3.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

procedure TTestXXHash3.TestChunkedDataKnownAnswer;
begin
  ExpectedString := '3D3D7245B763ACE8';
  ActualString := HashInstance.ComputeString(ChunkedData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TTestXXHash3.TestTwoKiBDataKnownAnswer;
var
  LData: TBytes;
  LIdx: Int32;
begin
  System.SetLength(LData, 2048);
  for LIdx := 0 to 2047 do
  begin
    LData[LIdx] := Byte(LIdx and $FF);
  end;
  ExpectedString := 'DD420471FF96BD00';
  ActualString := HashInstance.ComputeBytes(LData).ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TTestXXHash3.TestChunkedDataWithAsymmetricKeyKnownAnswer;
var
  LIHashWithKey: IHashWithKey;
  LKey: TBytes;
begin
  // key = $0123456789ABCDEF (little-endian bytes below)
  ExpectedString := 'FBF9CD92890CC82A';
  CheckTrue(Supports(HashInstance, IHashWithKey, LIHashWithKey),
    'HashInstance must support IHashWithKey');
  LKey := TBytes.Create($EF, $CD, $AB, $89, $67, $45, $23, $01);
  LIHashWithKey.Key := LKey;
  ActualString := LIHashWithKey.ComputeString(ChunkedData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TTestXXHash3.TestChunkedDataWithMaxUInt64AsKeyKnownAnswer;
var
  LIHashWithKey: IHashWithKey;
  LKey: TBytes;
  LIdx: Int32;
begin
  ExpectedString := '7DEFEE70FC854900';
  CheckTrue(Supports(HashInstance, IHashWithKey, LIHashWithKey),
    'HashInstance must support IHashWithKey');
  System.SetLength(LKey, System.SizeOf(UInt64));
  for LIdx := 0 to System.High(LKey) do
  begin
    LKey[LIdx] := $FF;
  end;
  LIHashWithKey.Key := LKey;
  ActualString := LIHashWithKey.ComputeString(ChunkedData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

{ THash64LengthKnownAnswerTestCase }

class function THash64LengthKnownAnswerTestCase.MakeData(ALength: Int32): TBytes;
var
  LIdx: Int32;
begin
  Result := nil;
  System.SetLength(Result, ALength);
  for LIdx := 0 to ALength - 1 do
  begin
    Result[LIdx] := Byte(LIdx and $FF);
  end;
end;

procedure THash64LengthKnownAnswerTestCase.TestLengthKnownAnswers;
var
  LData: TBytes;
  LIdx, LLength, LOffset, LChunk: Int32;
begin
  for LIdx := System.Low(KnownAnswerLengths) to System.High(KnownAnswerLengths) do
  begin
    LLength := KnownAnswerLengths[LIdx];
    LData := MakeData(LLength);
    ExpectedString := FLengthKnownAnswers[LIdx];

    ActualString := HashInstance.ComputeBytes(LData).ToString();
    CheckEquals(ExpectedString, ActualString,
      Format('Length %d: Expected %s but got %s.', [LLength, ExpectedString,
      ActualString]));

    HashInstance.Initialize();
    LOffset := 0;
    while LOffset < LLength do
    begin
      LChunk := 7;
      if LOffset + LChunk > LLength then
      begin
        LChunk := LLength - LOffset;
      end;
      HashInstance.TransformBytes(LData, LOffset, LChunk);
      System.Inc(LOffset, LChunk);
    end;
    ActualString := HashInstance.TransformFinal().ToString();
    CheckEquals(ExpectedString, ActualString,
      Format('Incremental, length %d: Expected %s but got %s.',
      [LLength, ExpectedString, ActualString]));
  end;
end;

procedure THash64LengthKnownAnswerTestCase.Test1000BytesWithAsymmetricKeyKnownAnswer;
var
  LIHashWithKey: IHashWithKey;
begin
  ExpectedString := FHashOf1000BytesWithAsymmetricKey;
  CheckTrue(Supports(HashInstance, IHashWithKey, LIHashWithKey),
    'HashInstance must support IHashWithKey');
  LIHashWithKey.Key := TBytes.Create($EF, $CD, $AB, $89, $67, $45, $23, $01);
  ActualString := LIHashWithKey.ComputeBytes(MakeData(1000)).ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

{ TTestRapidHash }

procedure TTestRapidHash.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateRapidHash();
  HashOfEmptyData := '0338DC4BE2CECDAE';
  HashOfDefaultData := 'FFBF72D5C447CD52';
  HashOfOnetoNine := '7E7D033B96B916A1';
  HashOfABCDE := 'C5FB18456266E8B0';
  HashOfDefaultDataWithMaxUInt64AsKey := '11B844B8D88A2831';
  FHashOf1000BytesWithAsymmetricKey := '948E7D3BB82751D9';
  FLengthKnownAnswers[0] := '0338DC4BE2CECDAE';
  FLengthKnownAnswers[1] := '4F23C791B16EBA02';
  FLengthKnownAnswers[2] := 'DBD091BCF57AE814';
  FLengthKnownAnswers[3] := '46FEF26DB4943ADF';
  FLengthKnownAnswers[4] := '7F403E573BB8EBC1';
  FLengthKnownAnswers[5] := 'DA56413FF396AF3E';
  FLengthKnownAnswers[6] := 'D6BFC1BCF7E9CA19';
  FLengthKnownAnswers[7] := '7508C9E74D5B5366';
  FLengthKnownAnswers[8] := 'C0186990F026B180';
  FLengthKnownAnswers[9] := 'EB4FF8393398A779';
  FLengthKnownAnswers[10] := 'ECD5ED3E946F9C91';
  FLengthKnownAnswers[11] := '635A714C24C02D64';
  FLengthKnownAnswers[12] := 'D1A6CC5FE6CF87F4';
  FLengthKnownAnswers[13] := 'E7E477A0DFFEAE1F';
  FLengthKnownAnswers[14] := 'AB742CAAB8765CD2';
  FLengthKnownAnswers[15] := '1E9A8D81B63DE536';
  FLengthKnownAnswers[16] := '07784269B17CBBFE';
  FLengthKnownAnswers[17] := '667174637FD34AE7';
  FLengthKnownAnswers[18] := 'ABAF0E2BDACF7E23';
  FLengthKnownAnswers[19] := 'A461A0B1D2F8656C';
  FLengthKnownAnswers[20] := '7AA1CBA714D28415';
  FLengthKnownAnswers[21] := '9D1612CDF44B1C42';
  FLengthKnownAnswers[22] := 'EEFA9C2E54FC0DF1';
  FLengthKnownAnswers[23] := 'A2F383F4B9260B9D';
  FLengthKnownAnswers[24] := 'FB71260237A1E7E9';
  FLengthKnownAnswers[25] := '289A29F3A6F04813';
  FLengthKnownAnswers[26] := '2A6BE558A956FAF3';
end;

procedure TTestRapidHash.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestRapidHashMicro }

procedure TTestRapidHashMicro.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateRapidHashMicro();
  HashOfEmptyData := '0338DC4BE2CECDAE';
  HashOfDefaultData := 'FFBF72D5C447CD52';
  HashOfOnetoNine := '7E7D033B96B916A1';
  HashOfABCDE := 'C5FB18456266E8B0';
  HashOfDefaultDataWithMaxUInt64AsKey := '11B844B8D88A2831';
  FHashOf1000BytesWithAsymmetricKey := '0019C905EE96B0B9';
  FLengthKnownAnswers[0] := '0338DC4BE2CECDAE';
  FLengthKnownAnswers[1] := '4F23C791B16EBA02';
  FLengthKnownAnswers[2] := 'DBD091BCF57AE814';
  FLengthKnownAnswers[3] := '46FEF26DB4943ADF';
  FLengthKnownAnswers[4] := '7F403E573BB8EBC1';
  FLengthKnownAnswers[5] := 'DA56413FF396AF3E';
  FLengthKnownAnswers[6] := 'D6BFC1BCF7E9CA19';
  FLengthKnownAnswers[7] := '7508C9E74D5B5366';
  FLengthKnownAnswers[8] := 'C0186990F026B180';
  FLengthKnownAnswers[9] := 'EB4FF8393398A779';
  FLengthKnownAnswers[10] := 'ECD5ED3E946F9C91';
  FLengthKnownAnswers[11] := '635A714C24C02D64';
  FLengthKnownAnswers[12] := 'D1A6CC5FE6CF87F4';
  FLengthKnownAnswers[13] := 'E7E477A0DFFEAE1F';
  FLengthKnownAnswers[14] := '8C7E35F2679BA33F';
  FLengthKnownAnswers[15] := 'C6541B258909F359';
  FLengthKnownAnswers[16] := 'CCE8222610EF0333';
  FLengthKnownAnswers[17] := '336EA990F5FCBD44';
  FLengthKnownAnswers[18] := 'A706652CAF6839EE';
  FLengthKnownAnswers[19] := '92E20B845ABF0627';
  FLengthKnownAnswers[20] := '8B36951F64741FB3';
  FLengthKnownAnswers[21] := '3158564C851D0C02';
  FLengthKnownAnswers[22] := '505691CBC238DEFC';
  FLengthKnownAnswers[23] := '2E92313653FF5963';
  FLengthKnownAnswers[24] := '77A7DD7578323289';
  FLengthKnownAnswers[25] := 'A2002B34AE08BEB8';
  FLengthKnownAnswers[26] := 'E2E33D1CFC2D95A5';
end;

procedure TTestRapidHashMicro.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestRapidHashNano }

procedure TTestRapidHashNano.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateRapidHashNano();
  HashOfEmptyData := '0338DC4BE2CECDAE';
  HashOfDefaultData := 'FFBF72D5C447CD52';
  HashOfOnetoNine := '7E7D033B96B916A1';
  HashOfABCDE := 'C5FB18456266E8B0';
  HashOfDefaultDataWithMaxUInt64AsKey := '11B844B8D88A2831';
  FHashOf1000BytesWithAsymmetricKey := '5D89E02A08107EC2';
  FLengthKnownAnswers[0] := '0338DC4BE2CECDAE';
  FLengthKnownAnswers[1] := '4F23C791B16EBA02';
  FLengthKnownAnswers[2] := 'DBD091BCF57AE814';
  FLengthKnownAnswers[3] := '46FEF26DB4943ADF';
  FLengthKnownAnswers[4] := '7F403E573BB8EBC1';
  FLengthKnownAnswers[5] := 'DA56413FF396AF3E';
  FLengthKnownAnswers[6] := 'D6BFC1BCF7E9CA19';
  FLengthKnownAnswers[7] := '7508C9E74D5B5366';
  FLengthKnownAnswers[8] := 'C0186990F026B180';
  FLengthKnownAnswers[9] := 'EB4FF8393398A779';
  FLengthKnownAnswers[10] := 'ECD5ED3E946F9C91';
  FLengthKnownAnswers[11] := '154059F965173DB2';
  FLengthKnownAnswers[12] := 'E3302D81A652122E';
  FLengthKnownAnswers[13] := '392712804DA62FE5';
  FLengthKnownAnswers[14] := '2BBB2D7C342E49D7';
  FLengthKnownAnswers[15] := 'CC67DA7A70C5719B';
  FLengthKnownAnswers[16] := '0378922294363ED9';
  FLengthKnownAnswers[17] := '45D21D1AD07DF9DF';
  FLengthKnownAnswers[18] := '0CFA1A10EEC7C0BF';
  FLengthKnownAnswers[19] := '6CF0D29DD73B5B1D';
  FLengthKnownAnswers[20] := '745F2F745AB768B9';
  FLengthKnownAnswers[21] := '180E783519DB3E0C';
  FLengthKnownAnswers[22] := '64B865CDAC15AC51';
  FLengthKnownAnswers[23] := '0CEBE53DE18834B6';
  FLengthKnownAnswers[24] := '1775E8A684A6A648';
  FLengthKnownAnswers[25] := 'DAE2370AD4FB35C2';
  FLengthKnownAnswers[26] := 'F6357A963B6BCDC9';
end;

procedure TTestRapidHashNano.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestFoldHash }

procedure TTestFoldHash.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateFoldHash();
  HashOfEmptyData := '01EE54DC4D5E9D2D';
  HashOfDefaultData := '73F9B71B6A456EF6';
  HashOfOnetoNine := 'ED648873AF4304E9';
  HashOfABCDE := '7D66B2BFB349FC59';
  HashOfDefaultDataWithMaxUInt64AsKey := '6BC5279B42354EC7';
  FHashOf1000BytesWithAsymmetricKey := '87395A048724811B';
  FLengthKnownAnswers[0] := '01EE54DC4D5E9D2D';
  FLengthKnownAnswers[1] := '42F4306FA6AC4EA0';
  FLengthKnownAnswers[2] := '0B74CBF0139A6787';
  FLengthKnownAnswers[3] := '8D8189574F35B357';
  FLengthKnownAnswers[4] := '8AE68C41BA5DCBE1';
  FLengthKnownAnswers[5] := '671DB6BD8F167901';
  FLengthKnownAnswers[6] := '92DEDDE89B505AF7';
  FLengthKnownAnswers[7] := 'E4A063C2D424C0EB';
  FLengthKnownAnswers[8] := 'D87F511970B393E0';
  FLengthKnownAnswers[9] := 'C1C3860E9F769EF1';
  FLengthKnownAnswers[10] := 'A4BC2A6D58DBBABF';
  FLengthKnownAnswers[11] := '831612ED083D245D';
  FLengthKnownAnswers[12] := 'D4133CED86EF6DD5';
  FLengthKnownAnswers[13] := 'BA2FC8F45CF9D734';
  FLengthKnownAnswers[14] := '32900AD711C9C465';
  FLengthKnownAnswers[15] := '6F16D2E3ACD36AE8';
  FLengthKnownAnswers[16] := 'BEE98CD7F9DD7A67';
  FLengthKnownAnswers[17] := 'DD286515D4806AC6';
  FLengthKnownAnswers[18] := '60F8BFCBCBC64122';
  FLengthKnownAnswers[19] := 'DA2A9395DC7BACFD';
  FLengthKnownAnswers[20] := 'F38B81F514ADD393';
  FLengthKnownAnswers[21] := 'EFA74A37F210F620';
  FLengthKnownAnswers[22] := '49250F90908361DA';
  FLengthKnownAnswers[23] := '1B15DF11AD55615E';
  FLengthKnownAnswers[24] := 'EF02B77BC4BDD42B';
  FLengthKnownAnswers[25] := 'CF9978433B613214';
  FLengthKnownAnswers[26] := '4B703A051D927D8D';
end;

procedure TTestFoldHash.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestFoldHashQuality }

procedure TTestFoldHashQuality.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateFoldHashQuality();
  HashOfEmptyData := 'CFBC9EAEBD51464B';
  HashOfDefaultData := '44FF8A011EE207A0';
  HashOfOnetoNine := 'BF4C626CAB4D0840';
  HashOfABCDE := '68E05280A7E4D102';
  HashOfDefaultDataWithMaxUInt64AsKey := '74A4F37067F10BEF';
  FHashOf1000BytesWithAsymmetricKey := 'ACB55F5EF2F5D07C';
  FLengthKnownAnswers[0] := 'CFBC9EAEBD51464B';
  FLengthKnownAnswers[1] := '6F94FE0E9DFC7B5D';
  FLengthKnownAnswers[2] := '7B52737E623BCEA8';
  FLengthKnownAnswers[3] := '3FF6CA11776F1BE6';
  FLengthKnownAnswers[4] := 'DF18526F7583163A';
  FLengthKnownAnswers[5] := 'F01FBD81DFFDCF3B';
  FLengthKnownAnswers[6] := '1B44D11D295EBA21';
  FLengthKnownAnswers[7] := '818E760AA450A0E8';
  FLengthKnownAnswers[8] := '7A5D887CBD164174';
  FLengthKnownAnswers[9] := '81CC28B1DAA2A58B';
  FLengthKnownAnswers[10] := '6B102E9FA963A3D2';
  FLengthKnownAnswers[11] := 'B4E6447F22C52641';
  FLengthKnownAnswers[12] := '783640263FF0882C';
  FLengthKnownAnswers[13] := 'E36DC8AD9E3EA592';
  FLengthKnownAnswers[14] := '50B23DF9F86A9FC4';
  FLengthKnownAnswers[15] := '106E11F53C9571B8';
  FLengthKnownAnswers[16] := '8DE2899CC3A2D4BA';
  FLengthKnownAnswers[17] := '71B9CD3F9E44DC22';
  FLengthKnownAnswers[18] := 'D7F6E0F3D8E8F5F3';
  FLengthKnownAnswers[19] := '69A7976A73EE567E';
  FLengthKnownAnswers[20] := 'FF8D71A3983D582E';
  FLengthKnownAnswers[21] := 'E58F390E568FCA72';
  FLengthKnownAnswers[22] := '5545894744117641';
  FLengthKnownAnswers[23] := 'D4C90EDABC9D29E7';
  FLengthKnownAnswers[24] := 'B69214F6A037417E';
  FLengthKnownAnswers[25] := '48566BDE0FFF15E2';
  FLengthKnownAnswers[26] := '6ADE87A79701C9E9';
end;

procedure TTestFoldHashQuality.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
// Hash64
RegisterTest(TTestFNV64);
RegisterTest(TTestFNV1a64);
RegisterTest(TTestMurmur2_64);
RegisterTest(TTestSipHash2_4);
RegisterTest(TTestXXHash64);
RegisterTest(TTestXXHash3);
RegisterTest(TTestRapidHash);
RegisterTest(TTestRapidHashMicro);
RegisterTest(TTestRapidHashNano);
RegisterTest(TTestFoldHash);
RegisterTest(TTestFoldHashQuality);
{$ELSE}
// Hash64
RegisterTest(TTestFNV64.Suite);
RegisterTest(TTestFNV1a64.Suite);
RegisterTest(TTestMurmur2_64.Suite);
RegisterTest(TTestSipHash2_4.Suite);
RegisterTest(TTestXXHash64.Suite);
RegisterTest(TTestXXHash3.Suite);
RegisterTest(TTestRapidHash.Suite);
RegisterTest(TTestRapidHashMicro.Suite);
RegisterTest(TTestRapidHashNano.Suite);
RegisterTest(TTestFoldHash.Suite);
RegisterTest(TTestFoldHashQuality.Suite);
{$ENDIF FPC}

end.
