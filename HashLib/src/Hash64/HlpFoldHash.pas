unit HlpFoldHash;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpBinaryPrimitives,
  HlpBitOperations,
  HlpHashLibTypes,
  HlpHashLibExceptions,
  HlpIHash,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult,
  HlpMultipleTransformNonBlock;

resourcestring
  SInvalidKeyLength = 'KeyLength Must Be Equal to %d';

type
  /// <summary>
  /// Common base of foldhash 0.2 by Orson Peters
  /// (https://github.com/orlp/foldhash).
  /// The whole message is hashed as a single byte slice (Hasher::write
  /// followed by Hasher::finish) using the fixed global seed, with the 64-bit
  /// key (little-endian) as the per-hasher seed, i.e. the equivalent of
  /// FixedState::with_seed(Key). Output matches the reference on
  /// little-endian platforms.
  /// </summary>
  TFoldHashBase = class abstract(TMultipleTransformNonBlock, IHash64,
    IHashWithKey, ITransformBlock)

  strict private
  var
    FKey: UInt64;

  const
    CKEY = UInt64(0);

    // to bypass Internal error (200706094) on FPC, We use "Typed Constant".
    // The fixed global seed (ARBITRARY6 .. ARBITRARY11).
    CSeeds: array [0 .. 5] of UInt64 = (UInt64($C0AC29B7C97C50DD),
      UInt64($3F84D5B5B5470917), UInt64($9216D5D98979FB1B),
      UInt64($D1310BA698DFB5AC), UInt64($2FFD72DBD01ADFB7),
      UInt64($B8E1AFED6A267E96));

    function GetKeyLength(): Int32;
    function GetKey: THashLibByteArray; inline;
    procedure SetKey(const AValue: THashLibByteArray); inline;

    class function Load(APtr: PByte): UInt64; static; inline;
    class function HashBytesShort(APtr: PByte; ALength: Int32;
      AAccumulator: UInt64): UInt64; static;
    class function HashBytesLong(APtr: PByte; ALength: Int32;
      AAccumulator: UInt64): UInt64; static;

  strict protected
  const
    CArbitrary0: UInt64 = UInt64($243F6A8885A308D3);
    CArbitrary3: UInt64 = UInt64($082EFA98EC4E6C89);
    CArbitrary4: UInt64 = UInt64($452821E638D01377);

    function GetPerHasherSeed(AKey: UInt64): UInt64; virtual; abstract;
    function Finish(AAccumulator: UInt64): UInt64; virtual; abstract;

    function ComputeAggregatedBytes(const AData: THashLibByteArray)
      : IHashResult; override;

    procedure CopyStateTo(AInstance: TFoldHashBase);

  public
    constructor Create();
    property KeyLength: Int32 read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;

  end;

  /// <summary>
  /// foldhash::fast - the variant optimized for speed.
  /// </summary>
  TFoldHash = class sealed(TFoldHashBase)
  strict protected
    function GetPerHasherSeed(AKey: UInt64): UInt64; override;
    function Finish(AAccumulator: UInt64): UInt64; override;
  public
    function Clone(): IHash; override;
  end;

  /// <summary>
  /// foldhash::quality - the variant optimized for statistical quality.
  /// </summary>
  TFoldHashQuality = class sealed(TFoldHashBase)
  strict protected
    function GetPerHasherSeed(AKey: UInt64): UInt64; override;
    function Finish(AAccumulator: UInt64): UInt64; override;
  public
    function Clone(): IHash; override;
  end;

implementation

{ TFoldHashBase }

constructor TFoldHashBase.Create;
begin
  inherited Create(8, 8);
  FKey := CKEY;
end;

class function TFoldHashBase.Load(APtr: PByte): UInt64;
begin
  Result := TBinaryPrimitives.ReadUInt64LittleEndian(APtr, 0);
end;

class function TFoldHashBase.HashBytesShort(APtr: PByte; ALength: Int32;
  AAccumulator: UInt64): UInt64;
var
  LS0, LS1: UInt64;
begin
  LS0 := AAccumulator;
  LS1 := CSeeds[1];
  if ALength >= 8 then
  begin
    LS0 := LS0 xor Load(APtr);
    LS1 := LS1 xor Load(APtr + ALength - 8);
  end
  else if ALength >= 4 then
  begin
    LS0 := LS0 xor TBinaryPrimitives.ReadUInt32LittleEndian(APtr, 0);
    LS1 := LS1 xor TBinaryPrimitives.ReadUInt32LittleEndian
      (APtr + ALength - 4, 0);
  end
  else if ALength > 0 then
  begin
    LS0 := LS0 xor UInt64(APtr[0]);
    LS1 := LS1 xor ((UInt64(APtr[ALength - 1]) shl 8) or
      UInt64(APtr[ALength shr 1]));
  end;
  Result := TBitOperations.FoldedMultiply64(LS0, LS1);
end;

class function TFoldHashBase.HashBytesLong(APtr: PByte; ALength: Int32;
  AAccumulator: UInt64): UInt64;
var
  LS0, LS1, LS2, LS3, LS4, LS5, LSeed0: UInt64;
begin
  LSeed0 := CSeeds[0];
  LS0 := AAccumulator;
  LS1 := LS0 + CSeeds[1];

  if ALength > 128 then
  begin
    LS2 := LS0 + CSeeds[2];
    LS3 := LS0 + CSeeds[3];

    if ALength > 256 then
    begin
      LS4 := LS0 + CSeeds[4];
      LS5 := LS0 + CSeeds[5];
      repeat
        LS0 := TBitOperations.FoldedMultiply64(Load(APtr) xor LS0,
          Load(APtr + 48) xor LSeed0);
        LS1 := TBitOperations.FoldedMultiply64(Load(APtr + 8) xor LS1,
          Load(APtr + 56) xor LSeed0);
        LS2 := TBitOperations.FoldedMultiply64(Load(APtr + 16) xor LS2,
          Load(APtr + 64) xor LSeed0);
        LS3 := TBitOperations.FoldedMultiply64(Load(APtr + 24) xor LS3,
          Load(APtr + 72) xor LSeed0);
        LS4 := TBitOperations.FoldedMultiply64(Load(APtr + 32) xor LS4,
          Load(APtr + 80) xor LSeed0);
        LS5 := TBitOperations.FoldedMultiply64(Load(APtr + 40) xor LS5,
          Load(APtr + 88) xor LSeed0);
        System.Inc(APtr, 96);
        System.Dec(ALength, 96);
      until ALength <= 256;
      LS0 := LS0 xor LS4;
      LS1 := LS1 xor LS5;
    end;

    repeat
      LS0 := TBitOperations.FoldedMultiply64(Load(APtr) xor LS0,
        Load(APtr + 32) xor LSeed0);
      LS1 := TBitOperations.FoldedMultiply64(Load(APtr + 8) xor LS1,
        Load(APtr + 40) xor LSeed0);
      LS2 := TBitOperations.FoldedMultiply64(Load(APtr + 16) xor LS2,
        Load(APtr + 48) xor LSeed0);
      LS3 := TBitOperations.FoldedMultiply64(Load(APtr + 24) xor LS3,
        Load(APtr + 56) xor LSeed0);
      System.Inc(APtr, 64);
      System.Dec(ALength, 64);
    until ALength <= 128;
    LS0 := LS0 xor LS2;
    LS1 := LS1 xor LS3;
  end;

  LS0 := TBitOperations.FoldedMultiply64(Load(APtr) xor LS0,
    Load(APtr + ALength - 16) xor LSeed0);
  LS1 := TBitOperations.FoldedMultiply64(Load(APtr + 8) xor LS1,
    Load(APtr + ALength - 8) xor LSeed0);
  if ALength >= 32 then
  begin
    LS0 := TBitOperations.FoldedMultiply64(Load(APtr + 16) xor LS0,
      Load(APtr + ALength - 32) xor LSeed0);
    LS1 := TBitOperations.FoldedMultiply64(Load(APtr + 24) xor LS1,
      Load(APtr + ALength - 24) xor LSeed0);
    if ALength >= 64 then
    begin
      LS0 := TBitOperations.FoldedMultiply64(Load(APtr + 32) xor LS0,
        Load(APtr + ALength - 48) xor LSeed0);
      LS1 := TBitOperations.FoldedMultiply64(Load(APtr + 40) xor LS1,
        Load(APtr + ALength - 40) xor LSeed0);
      if ALength >= 96 then
      begin
        LS0 := TBitOperations.FoldedMultiply64(Load(APtr + 48) xor LS0,
          Load(APtr + ALength - 64) xor LSeed0);
        LS1 := TBitOperations.FoldedMultiply64(Load(APtr + 56) xor LS1,
          Load(APtr + ALength - 56) xor LSeed0);
      end;
    end;
  end;
  Result := LS0 xor LS1;
end;

function TFoldHashBase.ComputeAggregatedBytes(const AData: THashLibByteArray)
  : IHashResult;
var
  LLength: Int32;
  LAccumulator: UInt64;
begin
  LLength := System.Length(AData);
  LAccumulator := TBitOperations.RotateRight64(GetPerHasherSeed(FKey),
    LLength and 63);
  if LLength <= 16 then
  begin
    LAccumulator := HashBytesShort(PByte(AData), LLength, LAccumulator);
  end
  else
  begin
    LAccumulator := HashBytesLong(PByte(AData), LLength, LAccumulator);
  end;
  Result := THashResult.Create(Finish(LAccumulator));
end;

procedure TFoldHashBase.CopyStateTo(AInstance: TFoldHashBase);
begin
  AInstance.FKey := FKey;
  FBuffer.Position := 0;
  AInstance.FBuffer.CopyFrom(FBuffer, FBuffer.Size);
  AInstance.BufferSize := BufferSize;
end;

function TFoldHashBase.GetKey: THashLibByteArray;
begin
  System.SetLength(Result, System.SizeOf(UInt64));
  TBinaryPrimitives.WriteUInt64LittleEndian(Result, 0, FKey);
end;

function TFoldHashBase.GetKeyLength: Int32;
begin
  Result := 8;
end;

procedure TFoldHashBase.SetKey(const AValue: THashLibByteArray);
begin
  if (AValue = nil) then
  begin
    FKey := CKEY;
  end
  else
  begin
    if System.Length(AValue) <> KeyLength then
    begin
      raise EArgumentHashLibException.CreateResFmt(@SInvalidKeyLength,
        [KeyLength]);
    end;
    FKey := TBinaryPrimitives.ReadUInt64LittleEndian(PByte(AValue), 0);
  end;
end;

{ TFoldHash }

function TFoldHash.GetPerHasherSeed(AKey: UInt64): UInt64;
begin
  Result := AKey xor CArbitrary3;
end;

function TFoldHash.Finish(AAccumulator: UInt64): UInt64;
begin
  Result := AAccumulator;
end;

function TFoldHash.Clone(): IHash;
var
  LHashInstance: TFoldHash;
begin
  LHashInstance := TFoldHash.Create();
  CopyStateTo(LHashInstance);
  Result := LHashInstance;
end;

{ TFoldHashQuality }

function TFoldHashQuality.GetPerHasherSeed(AKey: UInt64): UInt64;
begin
  Result := TBitOperations.FoldedMultiply64(AKey, CArbitrary4) xor CArbitrary3;
end;

function TFoldHashQuality.Finish(AAccumulator: UInt64): UInt64;
begin
  Result := TBitOperations.FoldedMultiply64(AAccumulator, CArbitrary0);
end;

function TFoldHashQuality.Clone(): IHash;
var
  LHashInstance: TFoldHashQuality;
begin
  LHashInstance := TFoldHashQuality.Create();
  CopyStateTo(LHashInstance);
  Result := LHashInstance;
end;

end.
