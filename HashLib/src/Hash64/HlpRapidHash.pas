unit HlpRapidHash;

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
  /// Common base of the rapidhash V3 family by Nicolas De Carli
  /// (https://github.com/Nicoshev/rapidhash), based on wyhash.
  /// The 64-bit key is the rapidhash seed (little-endian); the default
  /// secrets and the RAPIDHASH_FAST / RAPIDHASH_COMPACT configuration are
  /// used. Output matches the reference on little-endian platforms.
  /// </summary>
  TRapidHashBase = class abstract(TMultipleTransformNonBlock, IHash64,
    IHashWithKey, ITransformBlock)

  strict private
  var
    FKey: UInt64;

  const
    CKEY = UInt64(0);

    function GetKeyLength(): Int32;
    function GetKey: THashLibByteArray; inline;
    procedure SetKey(const AValue: THashLibByteArray); inline;

  strict protected
  const
    // to bypass Internal error (200706094) on FPC, We use "Typed Constant".
    CSecret: array [0 .. 7] of UInt64 = (UInt64($2D358DCCAA6C78A5),
      UInt64($8BB84B93962EACC9), UInt64($4B33A62ED433D4A3),
      UInt64($4D5A2DA51DE1AA47), UInt64($A0761D6478BD642F),
      UInt64($E7037ED1A0B428DB), UInt64($90ED1765281C388C),
      UInt64($AAAAAAAAAAAAAAAA));

    class function Read64(APtr: PByte): UInt64; static; inline;
    class function Mix(AX, AY: UInt64): UInt64; static; inline;

    /// <summary>
    /// Absorbs the bulk of an input longer than 16 bytes, advancing APtr and
    /// decrementing ARemaining past the consumed bulk blocks, and returns the
    /// updated seed. The caller then reads the final 16 bytes ending at
    /// APtr + ARemaining.
    /// </summary>
    function AbsorbLong(var APtr: PByte; var ARemaining: UInt64;
      ASeed: UInt64): UInt64; virtual; abstract;

    function ComputeAggregatedBytes(const AData: THashLibByteArray)
      : IHashResult; override;

    procedure CopyStateTo(AInstance: TRapidHashBase);

  public
    constructor Create();
    property KeyLength: Int32 read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;

  end;

  /// <summary>
  /// rapidhash V3 (the general purpose variant).
  /// </summary>
  TRapidHash = class sealed(TRapidHashBase)
  strict protected
    function AbsorbLong(var APtr: PByte; var ARemaining: UInt64;
      ASeed: UInt64): UInt64; override;
  public
    function Clone(): IHash; override;
  end;

  /// <summary>
  /// rapidhashMicro V3 (smaller code, 80-byte bulk stride).
  /// </summary>
  TRapidHashMicro = class sealed(TRapidHashBase)
  strict protected
    function AbsorbLong(var APtr: PByte; var ARemaining: UInt64;
      ASeed: UInt64): UInt64; override;
  public
    function Clone(): IHash; override;
  end;

  /// <summary>
  /// rapidhashNano V3 (smallest code, 48-byte bulk stride).
  /// </summary>
  TRapidHashNano = class sealed(TRapidHashBase)
  strict protected
    function AbsorbLong(var APtr: PByte; var ARemaining: UInt64;
      ASeed: UInt64): UInt64; override;
  public
    function Clone(): IHash; override;
  end;

implementation

{ TRapidHashBase }

constructor TRapidHashBase.Create;
begin
  inherited Create(8, 8);
  FKey := CKEY;
end;

class function TRapidHashBase.Read64(APtr: PByte): UInt64;
begin
  Result := TBinaryPrimitives.ReadUInt64LittleEndian(APtr, 0);
end;

class function TRapidHashBase.Mix(AX, AY: UInt64): UInt64;
begin
  Result := TBitOperations.FoldedMultiply64(AX, AY);
end;

procedure TRapidHashBase.CopyStateTo(AInstance: TRapidHashBase);
begin
  AInstance.FKey := FKey;
  FBuffer.Position := 0;
  AInstance.FBuffer.CopyFrom(FBuffer, FBuffer.Size);
  AInstance.BufferSize := BufferSize;
end;

function TRapidHashBase.ComputeAggregatedBytes(const AData: THashLibByteArray)
  : IHashResult;
var
  LPtr: PByte;
  LLength, LRemaining, LSeed, LA, LB, LLow, LHigh: UInt64;
begin
  LPtr := PByte(AData);
  LLength := UInt64(System.Length(AData));
  LRemaining := LLength;
  LSeed := FKey xor Mix(FKey xor CSecret[2], CSecret[1]);

  if LLength <= 16 then
  begin
    if LLength >= 4 then
    begin
      LSeed := LSeed xor LLength;
      if LLength >= 8 then
      begin
        LA := Read64(LPtr);
        LB := Read64(LPtr + LLength - 8);
      end
      else
      begin
        LA := TBinaryPrimitives.ReadUInt32LittleEndian(LPtr, 0);
        LB := TBinaryPrimitives.ReadUInt32LittleEndian(LPtr + LLength - 4, 0);
      end;
    end
    else if LLength > 0 then
    begin
      LA := (UInt64(LPtr[0]) shl 45) or UInt64(LPtr[LLength - 1]);
      LB := UInt64(LPtr[LLength shr 1]);
    end
    else
    begin
      LA := 0;
      LB := 0;
    end;
  end
  else
  begin
    LSeed := AbsorbLong(LPtr, LRemaining, LSeed);
    // the tail reads may reach back before LPtr, but never before the start
    // of AData since the total length is greater than 16.
    LA := Read64(LPtr + LRemaining - 16) xor LRemaining;
    LB := Read64(LPtr + LRemaining - 8);
  end;

  TBitOperations.Multiply64To128(LA xor CSecret[1], LB xor LSeed, LLow, LHigh);
  Result := THashResult.Create(Mix(LLow xor CSecret[7], LHigh xor CSecret[1]
    xor LRemaining));
end;

function TRapidHashBase.GetKey: THashLibByteArray;
begin
  System.SetLength(Result, System.SizeOf(UInt64));
  TBinaryPrimitives.WriteUInt64LittleEndian(Result, 0, FKey);
end;

function TRapidHashBase.GetKeyLength: Int32;
begin
  Result := 8;
end;

procedure TRapidHashBase.SetKey(const AValue: THashLibByteArray);
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

{ TRapidHash }

function TRapidHash.AbsorbLong(var APtr: PByte; var ARemaining: UInt64;
  ASeed: UInt64): UInt64;
var
  LPtr: PByte;
  LSee1, LSee2, LSee3, LSee4, LSee5, LSee6: UInt64;
begin
  LPtr := APtr;
  if ARemaining > 112 then
  begin
    LSee1 := ASeed;
    LSee2 := ASeed;
    LSee3 := ASeed;
    LSee4 := ASeed;
    LSee5 := ASeed;
    LSee6 := ASeed;
    repeat
      ASeed := Mix(Read64(LPtr) xor CSecret[0], Read64(LPtr + 8) xor ASeed);
      LSee1 := Mix(Read64(LPtr + 16) xor CSecret[1], Read64(LPtr + 24) xor LSee1);
      LSee2 := Mix(Read64(LPtr + 32) xor CSecret[2], Read64(LPtr + 40) xor LSee2);
      LSee3 := Mix(Read64(LPtr + 48) xor CSecret[3], Read64(LPtr + 56) xor LSee3);
      LSee4 := Mix(Read64(LPtr + 64) xor CSecret[4], Read64(LPtr + 72) xor LSee4);
      LSee5 := Mix(Read64(LPtr + 80) xor CSecret[5], Read64(LPtr + 88) xor LSee5);
      LSee6 := Mix(Read64(LPtr + 96) xor CSecret[6], Read64(LPtr + 104) xor LSee6);
      System.Inc(LPtr, 112);
      System.Dec(ARemaining, 112);
    until ARemaining <= 112;
    ASeed := ASeed xor LSee1;
    LSee2 := LSee2 xor LSee3;
    LSee4 := LSee4 xor LSee5;
    ASeed := ASeed xor LSee6;
    LSee2 := LSee2 xor LSee4;
    ASeed := ASeed xor LSee2;
  end;

  if ARemaining > 16 then
  begin
    ASeed := Mix(Read64(LPtr) xor CSecret[2], Read64(LPtr + 8) xor ASeed);
    if ARemaining > 32 then
    begin
      ASeed := Mix(Read64(LPtr + 16) xor CSecret[2], Read64(LPtr + 24) xor ASeed);
      if ARemaining > 48 then
      begin
        ASeed := Mix(Read64(LPtr + 32) xor CSecret[1], Read64(LPtr + 40) xor ASeed);
        if ARemaining > 64 then
        begin
          ASeed := Mix(Read64(LPtr + 48) xor CSecret[1], Read64(LPtr + 56) xor ASeed);
          if ARemaining > 80 then
          begin
            ASeed := Mix(Read64(LPtr + 64) xor CSecret[2], Read64(LPtr + 72) xor ASeed);
            if ARemaining > 96 then
            begin
              ASeed := Mix(Read64(LPtr + 80) xor CSecret[1], Read64(LPtr + 88) xor ASeed);
            end;
          end;
        end;
      end;
    end;
  end;

  APtr := LPtr;
  Result := ASeed;
end;

function TRapidHash.Clone(): IHash;
var
  LHashInstance: TRapidHash;
begin
  LHashInstance := TRapidHash.Create();
  CopyStateTo(LHashInstance);
  Result := LHashInstance;
end;

{ TRapidHashMicro }

function TRapidHashMicro.AbsorbLong(var APtr: PByte; var ARemaining: UInt64;
  ASeed: UInt64): UInt64;
var
  LPtr: PByte;
  LSee1, LSee2, LSee3, LSee4: UInt64;
begin
  LPtr := APtr;
  if ARemaining > 80 then
  begin
    LSee1 := ASeed;
    LSee2 := ASeed;
    LSee3 := ASeed;
    LSee4 := ASeed;
    repeat
      ASeed := Mix(Read64(LPtr) xor CSecret[0], Read64(LPtr + 8) xor ASeed);
      LSee1 := Mix(Read64(LPtr + 16) xor CSecret[1], Read64(LPtr + 24) xor LSee1);
      LSee2 := Mix(Read64(LPtr + 32) xor CSecret[2], Read64(LPtr + 40) xor LSee2);
      LSee3 := Mix(Read64(LPtr + 48) xor CSecret[3], Read64(LPtr + 56) xor LSee3);
      LSee4 := Mix(Read64(LPtr + 64) xor CSecret[4], Read64(LPtr + 72) xor LSee4);
      System.Inc(LPtr, 80);
      System.Dec(ARemaining, 80);
    until ARemaining <= 80;
    ASeed := ASeed xor LSee1;
    LSee2 := LSee2 xor LSee3;
    ASeed := ASeed xor LSee4;
    ASeed := ASeed xor LSee2;
  end;

  if ARemaining > 16 then
  begin
    ASeed := Mix(Read64(LPtr) xor CSecret[2], Read64(LPtr + 8) xor ASeed);
    if ARemaining > 32 then
    begin
      ASeed := Mix(Read64(LPtr + 16) xor CSecret[2], Read64(LPtr + 24) xor ASeed);
      if ARemaining > 48 then
      begin
        ASeed := Mix(Read64(LPtr + 32) xor CSecret[1], Read64(LPtr + 40) xor ASeed);
        if ARemaining > 64 then
        begin
          ASeed := Mix(Read64(LPtr + 48) xor CSecret[1], Read64(LPtr + 56) xor ASeed);
        end;
      end;
    end;
  end;

  APtr := LPtr;
  Result := ASeed;
end;

function TRapidHashMicro.Clone(): IHash;
var
  LHashInstance: TRapidHashMicro;
begin
  LHashInstance := TRapidHashMicro.Create();
  CopyStateTo(LHashInstance);
  Result := LHashInstance;
end;

{ TRapidHashNano }

function TRapidHashNano.AbsorbLong(var APtr: PByte; var ARemaining: UInt64;
  ASeed: UInt64): UInt64;
var
  LPtr: PByte;
  LSee1, LSee2: UInt64;
begin
  LPtr := APtr;
  if ARemaining > 48 then
  begin
    LSee1 := ASeed;
    LSee2 := ASeed;
    repeat
      ASeed := Mix(Read64(LPtr) xor CSecret[0], Read64(LPtr + 8) xor ASeed);
      LSee1 := Mix(Read64(LPtr + 16) xor CSecret[1], Read64(LPtr + 24) xor LSee1);
      LSee2 := Mix(Read64(LPtr + 32) xor CSecret[2], Read64(LPtr + 40) xor LSee2);
      System.Inc(LPtr, 48);
      System.Dec(ARemaining, 48);
    until ARemaining <= 48;
    ASeed := ASeed xor LSee1;
    ASeed := ASeed xor LSee2;
  end;

  if ARemaining > 16 then
  begin
    ASeed := Mix(Read64(LPtr) xor CSecret[2], Read64(LPtr + 8) xor ASeed);
    if ARemaining > 32 then
    begin
      ASeed := Mix(Read64(LPtr + 16) xor CSecret[2], Read64(LPtr + 24) xor ASeed);
    end;
  end;

  APtr := LPtr;
  Result := ASeed;
end;

function TRapidHashNano.Clone(): IHash;
var
  LHashInstance: TRapidHashNano;
begin
  LHashInstance := TRapidHashNano.Create();
  CopyStateTo(LHashInstance);
  Result := LHashInstance;
end;

end.
