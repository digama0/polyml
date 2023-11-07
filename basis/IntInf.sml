(*
    Title:      Standard Basis Library: IntInf structure and signature.
    Copyright   David Matthews 2000, 2016-17, 2023

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.
    
    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.
    
    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*)
signature INT_INF =
sig
    include INTEGER
    val divMod : int * int -> int * int
    val quotRem : int * int -> int * int
    val pow : int * Int.int -> int
    val log2 : int -> Int.int
    val orb : int * int -> int
    val xorb : int * int -> int
    val andb : int * int -> int
    val notb : int -> int
    val << : int * Word.word -> int
    val ~>> : int * Word.word -> int
end;

structure IntInf : INT_INF =
struct
    type int = LargeInt.int
    
    val quotRem = LibrarySupport.quotRem

    fun divMod (x, y) =
    let
        val (q, r) = quotRem(x, y)
    in
        (* If the remainder is zero or the same sign as the
           divisor then the result is the same as quotRem.
           Otherwise round down the quotient and round up the remainder. *)
        if r = 0 orelse (r < 0) = (y < 0)
        then (q, r)
        else (q-1, r+y)
    end

    (* Return the position of the highest bit set in the value. *)
    local
        val log2Long: int -> Int.int = RunCall.rtsCallFast1 "PolyLog2Arbitrary";
    in
        fun log2 (i: int) : Int.int =
            if i <= 0 then raise Domain
            else if LibrarySupport.largeIntIsSmall i
            then Word.toInt(LibrarySupport.log2Word(Word.fromLargeInt i))
            else log2Long i
    end

    local
    (* These are implemented in the RTS. *)
        val orbFn  : int * int -> int = RunCall.rtsCallFull2 "PolyOrArbitrary"
        and xorbFn : int * int -> int = RunCall.rtsCallFull2 "PolyXorArbitrary"
        and andbFn : int * int -> int = RunCall.rtsCallFull2 "PolyAndArbitrary"
        
        open LibrarySupport
    in
        fun orb(i, j) =
            if (largeIntIsSmall i andalso (largeIntIsSmall i orelse i < 0)) orelse (largeIntIsSmall j andalso j < 0)
            then (* Both are small or one is small and negative.  If it's negative all the bits in the sign bit and
                    up will be one. *)
                Word.toLargeIntX(Word.orb(Word.fromLargeInt i, Word.fromLargeInt j))
            else orbFn(i, j)
        
        fun andb(i, j) =
            if (largeIntIsSmall i andalso (largeIntIsSmall i orelse i >= 0)) orelse (largeIntIsSmall j andalso j >= 0)
            then (* All the bits in the sign bit and above will be zero. *)
                Word.toLargeIntX(Word.andb(Word.fromLargeInt i, Word.fromLargeInt j))
            else andbFn(i, j)
        
        fun xorb(i, j) =
            if largeIntIsSmall i andalso largeIntIsSmall j
            then Word.toLargeIntX(Word.xorb(Word.fromLargeInt i, Word.fromLargeInt j))
            else xorbFn(i, j)
    end
    
    (* notb is defined as ~ (i+1) and there doesn't seem to be much advantage
       in implementing it any other way. *)
    fun notb i = ~(i + 1)
    
    local
        fun power(acc: LargeInt.int, _, 0w0) = acc
        |   power(acc, n, i) =
                power(
                    if Word.andb(i, 0w1) = 0w1
                    then acc * n
                    else acc,
                    n * n, Word.>>(i, 0w1)
                    )
    in
        fun pow(i: LargeInt.int, j: Int.int) =
            if j < 0
            then(* Various exceptional cases. *)
            (
                if i = 0 then raise Div
                else if i = 1 then 1
                else if i = ~1
                then if Int.rem(j, 2) = 0 then (*even*) 1 else (*odd*) ~1
                else 0
            )
            else if LibrarySupport.isShortInt j
            then power(1, i, Word.fromInt j)
            else
            (* Long: This is possible only if int is arbitrary precision.  If the
               value to be multiplied is anything other than 0 or 1
               we'll exceed the maximum size of a cell. *)
                if i = 0 then 0
            else if i = 1 then 1
            else raise Size
    end

    (* These could be implemented in the RTS although I doubt if it's
       really worth it. *)
    local
        val maxShift = Word.fromInt Word.wordSize
        val fullShift = pow(2, Word.wordSize)
    in
        fun << (i: int, j: Word.word) =
           if j < maxShift
           then i * Word.toLargeInt(Word.<<(0w1, j))
           else <<(i * fullShift, j-maxShift)
    end
    
    fun ~>> (i: int, j: Word.word) =
        if LibrarySupport.largeIntIsSmall i
        then Word.toLargeIntX(Word.~>>(Word.fromLargeInt i, j))
        else LargeInt.div(i, pow(2, Word.toInt j))

    open LargeInt (* Inherit everything from LargeInt.  Do this last because it overrides the overloaded functions. *)
end;
