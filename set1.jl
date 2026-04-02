using Base64
#import Pkg; Pkg.add("OpenSSL")
using OpenSSL

# Challenge 1 - Convert hex to base64

hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
b64_str = base64encode(hex2bytes(hex_str))
sol_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

println("\nChallenge 1: ")
println(b64_str == sol_str) # true


# Challenge 2 - Fixed XOR

function xor_buffers(buf1::AbstractVector{UInt8}, buf2::AbstractVector{UInt8})::Vector{UInt8}
    if length(buf1) != length(buf2)
        throw(ArgumentError("Buffers must be of equal length"))
    end
    return [buf1[i] ⊻ buf2[i] for i in eachindex(buf1)]
end

hex_str1 = "1c0111001f010100061a024b53535009181c"
hex_str2 = "686974207468652062756c6c277320657965"
buf1 = hex2bytes(hex_str1)
buf2 = hex2bytes(hex_str2)

xordbufs = xor_buffers(buf1, buf2)
out_str = bytes2hex(xordbufs)
sol_str = "746865206b696420646f6e277420706c6179"

println("\nChallenge 2: ")
println(out_str == sol_str) # true


# Challenge 3 - Single-byte XOR cipher

function decrypt_xor(buf::Vector{<:Integer}, key::Integer)::Vector{UInt8}
    return [buf[i] ⊻ key for i in eachindex(buf)]
end

function score_buf(buf::Vector{UInt8})::Float64
    freq = Dict('a' => 8.167, 'b' => 1.492, 'c' => 2.782, 'd' => 4.253,
                'e' => 12.702, 'f' => 2.228, 'g' => 2.015, 'h' => 6.094,
                'i' => 6.966, 'j' => 0.153, 'k' => 0.772, 'l' => 4.025,
                'm' => 2.406, 'n' => 6.749, 'o' => 7.507, 'p' => 1.929,
                'q' => 0.095, 'r' => 5.987, 's' => 6.327, 't' => 9.056,
                'u' => 2.758, 'v' => 0.978, 'w' => 2.360, 'x' => 0.150,
                'y' => 1.974, 'z' => 0.074) # frequency of letters in English

    penalty = -length(buf) * 12.702

    score = sum(
        haskey(freq, Char(buf[i])) ? freq[Char(buf[i])] : penalty
        for i in eachindex(buf)
        )
    return score
end


function find_cypher(buf::Vector{<:Integer})::UInt8
    best_key = -1
    best_score = -Inf
    for key in UInt8.(0:127)
        decrypted_buf = decrypt_xor(buf, key)
        score = score_buf(decrypted_buf)
        if score > best_score
            best_score = score
            best_key = key
        end
    end
    return best_key
end

hex_str3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
buf3 = hex2bytes(hex_str3)
best_key = find_cypher(buf3) # 88
buf3_decrypted = decrypt_xor(buf3, best_key)
buf3_decrypted_str = String(buf3_decrypted)

println("\nChallenge 3: ")
println(best_key, "\n", buf3_decrypted_str) # "Cooking MC's like a pound of bacon"


# Challenge 4 - Detect single-character XOR

open("./data/dataS1C4.txt","r") do file
    best_key = -1
    best_score = -Inf
    best_line = ""
    for line in eachline(file)
        buf = hex2bytes(line)
        key = find_cypher(buf)
        decrypted_buf = decrypt_xor(buf, key)
        score = score_buf(decrypted_buf)
        if score > best_score
            best_score = score
            best_key = key
            best_line = line
        end
    end
    buf4 = hex2bytes(best_line)
    buf4_decrypted = decrypt_xor(buf4, best_key)
    buf4_decrypted_str = String(buf4_decrypted)
    println("\nChallenge 4: ")
    println(buf4_decrypted_str) # "Now that the party is jumping\n"
end


# Challenge 5 - Implement repeating-key XOR

poem = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key5 = "ICE"
sol5 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

function repeating_key_xor(poem_bytes::AbstractVector{UInt8}, key_bytes::AbstractVector{UInt8})::Vector{UInt8}
    key_length = length(key_bytes)
    return [poem_bytes[i] ⊻ key_bytes[(i-1) % key_length + 1] for i in eachindex(poem_bytes)]
end 

poem_bytes = codeunits(poem)
key_bytes = codeunits(key5)
encrypted_bytes = repeating_key_xor(poem_bytes, key_bytes)
encrypted_string = bytes2hex(encrypted_bytes)

println("\nChallenge 5: ")
println(sol5 == encrypted_string) #true 


# Challenge 6 - Break repeating-key XOR

function hamming_distance(bytes1::AbstractVector{UInt8}, bytes2::AbstractVector{UInt8})::Int
    return sum(count_ones(bytes1[i] ⊻ bytes2[i]) for i in eachindex(bytes1))
end

test61 = "this is a test"
test62 = "wokka wokka!!!"
ans_dist_test6 = 37

println("\nChallenge 6: ")
println("test is ", hamming_distance(codeunits(test61), codeunits(test62)) == ans_dist_test6) # true


function find_keysize(bytes::AbstractVector{UInt8})
    smallest_dists = [Inf, Inf, Inf]
    best_keysizes = [-1, -1, -1]
    
    for keysize in 2:40
        b1 = bytes[1 : keysize]
        b2 = bytes[keysize+1 : 2*keysize]
        b3 = bytes[2*keysize+1 : 3*keysize]
        b4 = bytes[3*keysize+1 : 4*keysize]
        
        d1 = hamming_distance(b1, b2) / keysize
        d2 = hamming_distance(b2, b3) / keysize
        d3 = hamming_distance(b3, b4) / keysize
        dist = (d1 + d2 + d3) / 3
        
        if dist < maximum(smallest_dists)
            worst_idx = argmax(smallest_dists)
            deleteat!(smallest_dists, worst_idx)
            deleteat!(best_keysizes, worst_idx)
            push!(smallest_dists, dist)
            push!(best_keysizes, keysize)
        end
    end
    return best_keysizes[sortperm(smallest_dists)]
end

function get_byte_blocks(bytes::AbstractVector{UInt8}, block_size::Int)::Vector{Vector{UInt8}}
    return [bytes[i:min(i + block_size - 1, end)] for i in 1:block_size:length(bytes)]
end

open("./data/dataS1C6.txt","r") do file
    raw_content = replace(read(file, String), "\n" => "")
    content_bytes = base64decode(raw_content)
    best_keysizes = find_keysize(content_bytes)

    for test_key in [29] # best_keysizes
        println("Testing keysize: ", test_key)

        blocks = get_byte_blocks(content_bytes, test_key)
        transposed = [[byte[i] for byte in blocks if i <= length(byte)] for i in 1:test_key]

        real_key = UInt8[]
        for block in transposed
            key_byte = find_cypher(block)
            push!(real_key, key_byte)
        end

        final_key_str = String(real_key)
        println("Detected Key: ", final_key_str, "\n")

        final_bytes = repeating_key_xor(content_bytes, codeunits(final_key_str))
        println(String(final_bytes))
    end
end


# Challenge 7 - AES in ECB mode

raw_data = replace(read("./data/dataS1C7.txt", String), "\n" => "")
ciphertext = base64decode(raw_data)


ctx = OpenSSL.EvpCipherContext()
ciph = OpenSSL.EvpAES128ECB()
key7 = Vector{UInt8}("YELLOW SUBMARINE")  #16 bytes long

OpenSSL.decrypt_init(ctx, ciph, key7, zeros(UInt8, 16))

in_data = IOBuffer(ciphertext)
out_data = IOBuffer()

OpenSSL.cipher(ctx, in_data, out_data)

seekstart(out_data)
result = read(out_data, String)

println("\nChallenge 7: ")
println(result)

# decrypt_init(evp_cipher_ctx::EvpCipherContext, evp_cipher::OpenSSL.EvpCipher, symetric_key::Vector{UInt8}, init_vector::Vector{UInt8})
# cipher(evp_cipher_ctx::EvpCipherContext, in_io::IO, out_io::IO)


# Challenge 8 - Detect AES in ECB mode

raw_data8 = replace(read("./data/dataS1C8.txt", String), "\n" => "")
ciphertext8 = hex2bytes(raw_data8)
blocks = [ciphertext8[i:i+15] for i in 1:16:length(ciphertext8)]

duplicates = length(blocks) - length(unique(blocks))

println("\nChallenge 8: ")
if length(duplicates) > 0
    println("ECB detected")
end
